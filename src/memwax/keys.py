"""Local Ed25519 signing keys for amber baselines.

Keys live in the user's memwax home, never inside a project:

    $MEMWAX_HOME (default ~/.memwax)/keys/
        amber_ed25519.key      private key, PKCS#8 PEM (encrypted if MEMWAX_KEY_PASSPHRASE is set)
        amber_ed25519.pub      public key, base64 of the 32 raw bytes
        trusted/*.pub          extra public keys whose baselines you accept (e.g. a teammate or CI)

Keeping keys outside the project means an attacker who can write to the project's
memory files (the threat memwax is about) cannot also re-sign a baseline, unless they
can also read your home directory.
"""

from __future__ import annotations

import base64
import contextlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from memwax.hashing import sha256_bytes

PRIVATE_NAME = "amber_ed25519.key"
PUBLIC_NAME = "amber_ed25519.pub"
PASSPHRASE_ENV = "MEMWAX_KEY_PASSPHRASE"  # noqa: S105 - env var name, not a secret


class KeyStoreError(Exception):
    """Raised for missing, unreadable, or malformed keys."""


def memwax_home() -> Path:
    override = os.environ.get("MEMWAX_HOME")
    return Path(override).expanduser() if override else Path.home() / ".memwax"


def keys_dir() -> Path:
    return memwax_home() / "keys"


def key_id(public_raw: bytes) -> str:
    return sha256_bytes(public_raw)[:16]


def public_raw(public: Ed25519PublicKey) -> bytes:
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def encode_public(public: Ed25519PublicKey) -> str:
    return base64.b64encode(public_raw(public)).decode("ascii")


def decode_public(text: str) -> Ed25519PublicKey:
    raw = base64.b64decode(text.strip(), validate=True)
    if len(raw) != 32:
        raise KeyStoreError("public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


@dataclass
class SigningKey:
    private: Ed25519PrivateKey

    @property
    def public(self) -> Ed25519PublicKey:
        return self.private.public_key()

    @property
    def key_id(self) -> str:
        return key_id(public_raw(self.public))

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self.private.sign(message)).decode("ascii")


def verify_signature(public: Ed25519PublicKey, message: bytes, signature_b64: str) -> bool:
    try:
        public.verify(base64.b64decode(signature_b64, validate=True), message)
    except (InvalidSignature, ValueError):
        return False
    return True


def _passphrase() -> bytes | None:
    value = os.environ.get(PASSPHRASE_ENV)
    return value.encode("utf-8") if value else None


def _restrict(path: Path) -> None:
    # On POSIX this makes the file owner-only. On Windows chmod only toggles the
    # read-only bit; the file is protected by the user-profile ACLs instead.
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


def generate_key(directory: Path | None = None, *, overwrite: bool = False) -> SigningKey:
    directory = directory or keys_dir()
    private_path = directory / PRIVATE_NAME
    if private_path.exists() and not overwrite:
        raise KeyStoreError(f"a key already exists at {private_path}")
    directory.mkdir(parents=True, exist_ok=True)
    key = SigningKey(Ed25519PrivateKey.generate())
    passphrase = _passphrase()
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    pem = key.private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    _restrict(private_path)
    (directory / PUBLIC_NAME).write_text(encode_public(key.public) + "\n", encoding="ascii")
    return key


def load_key(directory: Path | None = None) -> SigningKey:
    directory = directory or keys_dir()
    private_path = directory / PRIVATE_NAME
    if not private_path.exists():
        raise KeyStoreError(f"no signing key at {private_path}")
    try:
        private = serialization.load_pem_private_key(
            private_path.read_bytes(), password=_passphrase()
        )
    except (ValueError, TypeError) as exc:
        raise KeyStoreError(f"cannot load {private_path}: {exc}") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise KeyStoreError(f"{private_path} is not an Ed25519 key")
    return SigningKey(private)


def load_or_create_key(directory: Path | None = None) -> tuple[SigningKey, bool]:
    directory = directory or keys_dir()
    if (directory / PRIVATE_NAME).exists():
        return load_key(directory), False
    return generate_key(directory), True


def trusted_public_keys(
    directory: Path | None = None, extra: list[Path] | None = None
) -> dict[str, Ed25519PublicKey]:
    """Own public key + keys in keys/trusted/ + any explicitly passed files, by key id."""
    directory = directory or keys_dir()
    candidates: list[Path] = []
    own = directory / PUBLIC_NAME
    if own.exists():
        candidates.append(own)
    trusted = directory / "trusted"
    if trusted.is_dir():
        candidates.extend(sorted(trusted.glob("*.pub")))
    candidates.extend(extra or [])
    keys: dict[str, Ed25519PublicKey] = {}
    for path in candidates:
        try:
            public = decode_public(path.read_text(encoding="ascii"))
        except (OSError, ValueError, KeyStoreError):
            continue
        keys[key_id(public_raw(public))] = public
    return keys
