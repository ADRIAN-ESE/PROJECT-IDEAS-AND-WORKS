"""Cryptographic helpers: key derivation, AES-256-GCM sealing, TOTP, tokens, backup codes."""
import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def load_master_key(instance_dir: Path) -> bytes:
    """32-byte master key from SS_MASTER_KEY (base64) or instance/master.key (created 0600)."""
    env = os.environ.get("SS_MASTER_KEY")
    if env:
        key = base64.b64decode(env)
        if len(key) != 32:
            raise RuntimeError("SS_MASTER_KEY must be 32 bytes, base64-encoded")
        return key
    path = Path(instance_dir) / "master.key"
    if path.exists():
        return base64.b64decode(path.read_text().strip())
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(base64.b64encode(key).decode())
    return key


class KeyRing:
    """Purpose-bound subkeys derived from the master key with HKDF-SHA256."""

    def __init__(self, master: bytes):
        self._master, self._cache = master, {}

    def get(self, purpose: str) -> bytes:
        if purpose not in self._cache:
            self._cache[purpose] = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                                        info=b"secureshare/v1/" + purpose.encode()).derive(self._master)
        return self._cache[purpose]


def seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def hmac_hex(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- TOTP (RFC 6238)
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_code(secret_b32: str, step: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), "sha1").digest()
    off = digest[-1] & 0x0F
    num = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{num:06d}"


def verify_totp(secret_b32: str, code: str, last_step: int = 0, window: int = 1):
    """Return the matching time-step (> last_step, so a code can't be replayed) or None."""
    if not (len(code) == 6 and code.isdigit()):
        return None
    now, found = int(time.time()) // 30, None
    for step in range(now - window, now + window + 1):
        if hmac.compare_digest(totp_code(secret_b32, step), code) and step > last_step:
            found = step
    return found


def otpauth_uri(issuer: str, account: str, secret: str) -> str:
    from urllib.parse import quote
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}"
            f"&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30")


# ---------------------------------------------------------------- backup codes
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def new_backup_codes(n: int = 10):
    return ["".join(secrets.choice(_ALPHABET) for _ in range(8)) for _ in range(n)]


def normalize_code(code: str) -> str:
    return code.replace(" ", "").replace("-", "").upper()


def format_backup(code: str) -> str:
    return f"{code[:4]}-{code[4:]}"
