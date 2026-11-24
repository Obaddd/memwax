import json
import subprocess

import pytest

from memwax.amber import (
    AmberError,
    baseline_path,
    create_baseline,
    load_object,
    verify_baseline,
)
from memwax.cli import main
from memwax.keys import (
    PRIVATE_NAME,
    KeyStoreError,
    generate_key,
    keys_dir,
    load_key,
    load_or_create_key,
)
from memwax.monitor import Monitor


@pytest.fixture
def key():
    return load_or_create_key()[0]


def test_key_is_created_outside_the_project(workspace, key):
    assert keys_dir().exists()
    assert workspace.root not in keys_dir().parents
    assert not list(workspace.root.rglob(PRIVATE_NAME))


def test_key_round_trip_and_refuses_overwrite(key):
    assert load_key().key_id == key.key_id
    with pytest.raises(KeyStoreError):
        generate_key()


def test_encrypted_key_needs_passphrase(tmp_path, monkeypatch):
    monkeypatch.setenv("MEMWAX_KEY_PASSPHRASE", "correct horse")
    directory = tmp_path / "enc"
    generate_key(directory)
    assert b"ENCRYPTED" in (directory / PRIVATE_NAME).read_bytes()
    monkeypatch.setenv("MEMWAX_KEY_PASSPHRASE", "wrong")
    with pytest.raises(KeyStoreError):
        load_key(directory)


def test_clean_baseline_verifies(workspace, key):
    baseline = create_baseline(workspace, key, note="first")
    assert set(baseline.files) == {"CLAUDE.md", "memory/prefs.md"}
    result = verify_baseline(workspace)
    assert result.signature_ok and result.integrity_ok
    assert result.drift.clean and result.drift.unchanged == 2


def test_drift_reports_added_changed_removed(workspace, key):
    create_baseline(workspace, key)
    (workspace.root / "CLAUDE.md").write_text("tampered\n", "utf-8")
    (workspace.root / "memory" / "prefs.md").unlink()
    (workspace.root / "memory" / "extra.md").write_text("new\n", "utf-8")
    drift = verify_baseline(workspace).drift
    assert drift.added == ["memory/extra.md"]
    assert drift.changed == ["CLAUDE.md"]
    assert drift.removed == ["memory/prefs.md"]
    assert drift.unchanged == 0


def test_object_store_keeps_baseline_content(workspace, key):
    baseline = create_baseline(workspace, key)
    digest = baseline.files["CLAUDE.md"]["sha256"]
    original = (workspace.root / "CLAUDE.md").read_bytes()
    assert load_object(workspace, digest) == original


def test_tampered_object_is_rejected(workspace, key):
    baseline = create_baseline(workspace, key)
    digest = baseline.files["CLAUDE.md"]["sha256"]
    obj = workspace.amber_dir / "objects" / digest[:2] / digest
    obj.write_bytes(b"swapped")
    assert load_object(workspace, digest) is None


def test_edited_baseline_fails_signature(workspace, key):
    create_baseline(workspace, key)
    path = baseline_path(workspace)
    data = json.loads(path.read_text("utf-8"))
    # Attacker "launders" their change by updating the baseline hash.
    (workspace.root / "CLAUDE.md").write_text("tampered\n", "utf-8")
    import hashlib

    data["manifest"]["files"]["CLAUDE.md"]["sha256"] = hashlib.sha256(b"tampered\n").hexdigest()
    path.write_text(json.dumps(data), "utf-8")
    result = verify_baseline(workspace)
    assert not result.signature_ok
    assert not result.integrity_ok
    assert any("INVALID" in p for p in result.integrity_problems)


def test_baseline_resigned_with_attacker_key_is_untrusted(workspace, key, tmp_path):
    create_baseline(workspace, key)
    attacker = generate_key(tmp_path / "attacker-keys")
    # The attacker re-creates the whole baseline with their own key (and embeds their pubkey).
    create_baseline(workspace, attacker)
    result = verify_baseline(workspace)
    assert not result.signature_ok
    assert any("not in your trusted keys" in p for p in result.integrity_problems)
    # ...but if you explicitly trust that public key, it verifies.
    pub = tmp_path / "attacker-keys" / "amber_ed25519.pub"
    assert verify_baseline(workspace, extra_pubkeys=[pub]).signature_ok


def test_trusted_dir_keys_are_accepted(workspace, tmp_path):
    teammate = generate_key(tmp_path / "teammate")
    create_baseline(workspace, teammate)
    trusted = keys_dir() / "trusted"
    trusted.mkdir(parents=True)
    (trusted / "teammate.pub").write_text(
        (tmp_path / "teammate" / "amber_ed25519.pub").read_text("ascii"), "ascii"
    )
    assert verify_baseline(workspace).signature_ok


def test_log_truncation_after_baseline_is_detected(workspace, key):
    Monitor(workspace, use_git=False).poll_once()
    create_baseline(workspace, key)
    log = workspace.log_path
    lines = log.read_text("utf-8").splitlines(keepends=True)
    log.write_text("".join(lines[:-2]), "utf-8")  # drop the amber entry and the head before it
    result = verify_baseline(workspace)
    assert result.signature_ok
    assert any("truncated" in p for p in result.integrity_problems)


def test_missing_baseline_raises(workspace):
    with pytest.raises(AmberError):
        verify_baseline(workspace)


def test_cli_amber_flow(project, capsys):
    root = ["--root", str(project)]
    assert main([*root, "init"]) == 0
    assert main([*root, "amber", "create", "--note", "known good"]) == 0
    assert main([*root, "amber", "verify"]) == 0
    assert "Drift: none" in capsys.readouterr().out
    (project / "CLAUDE.md").write_text("poisoned\n", "utf-8")
    assert main([*root, "amber", "verify"]) == 1
    assert "~ CLAUDE.md" in capsys.readouterr().out
    assert main([*root, "amber", "verify", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["drift"]["changed"] == ["CLAUDE.md"]
    assert main([*root, "key", "show"]) == 0


def test_private_key_never_tracked_by_git(git_project):
    """Even if someone points MEMWAX_HOME into a repo, the .gitignore keeps keys out."""
    from pathlib import Path

    repo_gitignore = Path(__file__).resolve().parents[1] / ".gitignore"
    text = repo_gitignore.read_text("utf-8")
    assert "*.key" in text and ".memwax/" in text
    # The project's own .memwax/.gitignore (written by init) hides all memwax state.
    from memwax.workspace import Workspace

    Workspace(git_project).init()
    (git_project / ".memwax" / "x").write_text("x", "utf-8")
    status = subprocess.run(
        ["git", "-C", str(git_project), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert ".memwax" not in status
