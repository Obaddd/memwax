"""Amber baselines: signed snapshots of a known-good memory state.

`create_baseline` hashes every tracked file, stores a copy of each file's content in a
content-addressed object store (so later drift can be diffed line by line), records the
change-log head, and signs the whole manifest with the local Ed25519 key.

`verify_baseline` checks, in order:

1. the signature, against a *locally trusted* public key (the public key embedded in the
   baseline is informational only; trusting it would let anyone re-sign);
2. that the change log still verifies and still contains the head recorded at baseline
   time (catches the log being truncated or rewritten after the baseline);
3. drift: files added, changed, or removed since the baseline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from memwax import __version__
from memwax.changelog import ChangeLog, utc_now
from memwax.hashing import canonical_json, sha256_bytes, sha256_json
from memwax.keys import (
    KeyStoreError,
    SigningKey,
    decode_public,
    encode_public,
    public_raw,
    trusted_public_keys,
    verify_signature,
)
from memwax.keys import key_id as compute_key_id
from memwax.workspace import Workspace, atomic_write_text

FORMAT = "memwax-amber/1"
BASELINE_NAME = "baseline.json"


class AmberError(Exception):
    pass


@dataclass
class FileRecord:
    sha256: str
    size: int
    lines: int

    def to_dict(self) -> dict[str, Any]:
        return {"sha256": self.sha256, "size": self.size, "lines": self.lines}


@dataclass
class Baseline:
    manifest: dict[str, Any]
    signature: str

    @property
    def files(self) -> dict[str, dict[str, Any]]:
        return self.manifest["files"]

    @property
    def digest(self) -> str:
        return sha256_json(self.manifest)

    def to_dict(self) -> dict[str, Any]:
        return {"manifest": self.manifest, "signature": self.signature}


@dataclass
class DriftReport:
    added: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    unchanged: int = 0

    @property
    def clean(self) -> bool:
        return not (self.added or self.changed or self.removed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "added": self.added,
            "changed": self.changed,
            "removed": self.removed,
            "unchanged": self.unchanged,
        }


@dataclass
class VerifyResult:
    signature_ok: bool
    signer: str | None
    integrity_problems: list[str]
    drift: DriftReport
    baseline: Baseline | None

    @property
    def integrity_ok(self) -> bool:
        return self.signature_ok and not self.integrity_problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature_ok": self.signature_ok,
            "signer": self.signer,
            "integrity_ok": self.integrity_ok,
            "integrity_problems": self.integrity_problems,
            "drift": self.drift.to_dict(),
            "baseline_created_at": self.baseline.manifest["created_at"] if self.baseline else None,
            "baseline_digest": self.baseline.digest if self.baseline else None,
        }


# ----- object store ------------------------------------------------------------
def objects_dir(ws: Workspace) -> Path:
    return ws.amber_dir / "objects"


def store_object(ws: Workspace, data: bytes) -> str:
    digest = sha256_bytes(data)
    path = objects_dir(ws) / digest[:2] / digest
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return digest


def load_object(ws: Workspace, digest: str) -> bytes | None:
    """Return stored bytes only if they still hash to `digest`."""
    path = objects_dir(ws) / digest[:2] / digest
    if not path.exists():
        return None
    data = path.read_bytes()
    return data if sha256_bytes(data) == digest else None


# ----- create ------------------------------------------------------------------
def _count_lines(data: bytes) -> int:
    if not data:
        return 0
    return data.count(b"\n") + (0 if data.endswith(b"\n") else 1)


def current_records(ws: Workspace) -> dict[str, FileRecord]:
    records: dict[str, FileRecord] = {}
    for path in ws.discover():
        data = path.read_bytes()
        records[ws.relpath(path)] = FileRecord(sha256_bytes(data), len(data), _count_lines(data))
    return records


def baseline_path(ws: Workspace) -> Path:
    return ws.amber_dir / BASELINE_NAME


def create_baseline(ws: Workspace, key: SigningKey, *, note: str = "") -> Baseline:
    files: dict[str, dict[str, Any]] = {}
    for path in ws.discover():
        data = path.read_bytes()
        store_object(ws, data)
        record = FileRecord(sha256_bytes(data), len(data), _count_lines(data))
        files[ws.relpath(path)] = record.to_dict()
    log = ChangeLog(ws.log_path)
    seq, head = log.head()
    manifest = {
        "format": FORMAT,
        "created_at": utc_now(),
        "created_by": f"memwax {__version__}",
        "note": note,
        "files": files,
        "log_head": {"seq": seq, "hash": head},
        "key_id": key.key_id,
        "public_key": encode_public(key.public),
    }
    baseline = Baseline(manifest, key.sign(canonical_json(manifest)))
    atomic_write_text(baseline_path(ws), json.dumps(baseline.to_dict(), indent=2) + "\n")
    log.append(
        "amber",
        ".memwax/amber/baseline.json",
        sha256=baseline.digest,
        source={"kind": "memwax", "action": "amber create"},
        extra={"files": len(files), "key_id": key.key_id},
    )
    return baseline


# ----- verify ------------------------------------------------------------------
def load_baseline(ws: Workspace, path: Path | None = None) -> Baseline:
    path = path or baseline_path(ws)
    if not path.exists():
        raise AmberError(f"no amber baseline at {path}; run `memwax amber create`")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return Baseline(dict(data["manifest"]), str(data["signature"]))
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise AmberError(f"baseline at {path} is malformed: {exc}") from exc


def compute_drift(baseline_files: dict[str, dict[str, Any]], ws: Workspace) -> DriftReport:
    current = current_records(ws)
    report = DriftReport()
    for rel in sorted(set(baseline_files) | set(current)):
        before, after = baseline_files.get(rel), current.get(rel)
        if before is None:
            report.added.append(rel)
        elif after is None:
            report.removed.append(rel)
        elif before.get("sha256") != after.sha256:
            report.changed.append(rel)
        else:
            report.unchanged += 1
    return report


def verify_baseline(
    ws: Workspace,
    *,
    keys_directory: Path | None = None,
    extra_pubkeys: list[Path] | None = None,
    baseline_file: Path | None = None,
) -> VerifyResult:
    baseline = load_baseline(ws, baseline_file)
    problems: list[str] = []

    # 1. signature against locally trusted keys only.
    trusted = trusted_public_keys(keys_directory, extra_pubkeys)
    key_id = str(baseline.manifest.get("key_id", ""))
    signature_ok = False
    signer = None
    public = trusted.get(key_id)
    if public is None:
        problems.append(f"baseline signed by key {key_id or '?'} which is not in your trusted keys")
    elif verify_signature(public, canonical_json(baseline.manifest), baseline.signature):
        signature_ok = True
        signer = key_id
    else:
        problems.append("baseline signature is INVALID (baseline was modified after signing)")
    try:
        embedded = decode_public(str(baseline.manifest.get("public_key", "")))
        if compute_key_id(public_raw(embedded)) != key_id:
            problems.append("embedded public key does not match key_id")
    except (ValueError, KeyStoreError):
        problems.append("embedded public key is malformed")

    # 2. the change log must still contain the head recorded at baseline time.
    log = ChangeLog(ws.log_path)
    chain = log.verify()
    if not chain.ok:
        problems.append(f"change log hash chain is broken ({len(chain.problems)} problem(s))")
    head = baseline.manifest.get("log_head", {})
    head_seq, head_hash = int(head.get("seq", 0)), str(head.get("hash", ""))
    if head_seq > 0:
        match = next((e for e in log.entries() if e.seq == head_seq), None)
        if match is None:
            problems.append(f"change log no longer contains entry #{head_seq} (truncated?)")
        elif match.hash != head_hash:
            problems.append(f"change log entry #{head_seq} differs from the baseline's record")

    # 3. drift.
    drift = compute_drift(baseline.files, ws)
    return VerifyResult(signature_ok, signer, problems, drift, baseline)
