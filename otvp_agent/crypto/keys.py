"""Ed25519 key management for OTVP agents."""
from __future__ import annotations
import base64, json
from dataclasses import dataclass
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
    load_pem_private_key, load_pem_public_key,
)


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class PublicKeyRef:
    key_id: str
    public_key_b64: str
    entity_id: str
    entity_type: str
    certification_ref: str | None = None
    def to_dict(self) -> dict:
        d = {"key_id": self.key_id, "public_key_b64": self.public_key_b64,
             "entity_id": self.entity_id, "entity_type": self.entity_type}
        if self.certification_ref: d["certification_ref"] = self.certification_ref
        return d


@dataclass(frozen=True)
class KeyPair:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls) -> KeyPair:
        pk = Ed25519PrivateKey.generate()
        return cls(private_key=pk, public_key=pk.public_key())

    @classmethod
    def from_pem_files(cls, private_path: str | Path, public_path: str | Path) -> KeyPair:
        priv = load_pem_private_key(Path(private_path).read_bytes(), password=None)
        pub = load_pem_public_key(Path(public_path).read_bytes())
        assert isinstance(priv, Ed25519PrivateKey) and isinstance(pub, Ed25519PublicKey)
        return cls(private_key=priv, public_key=pub)

    @classmethod
    def from_private_pem(cls, pem_data: bytes) -> KeyPair:
        priv = load_pem_private_key(pem_data, password=None)
        assert isinstance(priv, Ed25519PrivateKey)
        return cls(private_key=priv, public_key=priv.public_key())

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self.private_key.sign(data)).decode("ascii")

    def verify(self, signature_b64: str, data: bytes) -> bool:
        try:
            self.public_key.verify(base64.b64decode(signature_b64), data)
            return True
        except Exception:
            return False

    def sign_json(self, obj: dict) -> str:
        return self.sign(canonical_json(obj))

    def verify_json(self, signature_b64: str, obj: dict) -> bool:
        return self.verify(signature_b64, canonical_json(obj))

    def public_key_b64(self) -> str:
        raw = self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    def export_private_pem(self) -> bytes:
        return self.private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    def export_public_pem(self) -> bytes:
        return self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def save(self, private_path: str | Path, public_path: str | Path) -> None:
        Path(private_path).write_bytes(self.export_private_pem())
        Path(public_path).write_bytes(self.export_public_pem())
