"""
Signing primitives for Vouch.

Every verified company gets an Ed25519 keypair. The private key signs
offer payloads; the public key (published in the company's hiring-trust
file) lets anyone -- including a candidate who has never talked to
Vouch's server -- check that signature independently.
"""
import base64
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.exceptions import InvalidSignature


def sha256_hex(data: bytes) -> str:
    """Hex SHA-256 digest of raw bytes. Used to fingerprint stamped PDFs."""
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(payload: dict) -> bytes:
    """
    Deterministic JSON encoding: sorted keys, no extra whitespace.
    Signing and verifying MUST both use this so the same payload always
    produces the same bytes -- otherwise a valid signature could appear
    to fail just because keys were reordered.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def new_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def private_key_to_pem(priv: Ed25519PrivateKey) -> str:
    return priv.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode()


def public_key_to_pem(pub: Ed25519PublicKey) -> str:
    return pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


def private_key_from_pem(pem: str) -> Ed25519PrivateKey:
    return load_pem_private_key(pem.encode(), password=None)


def public_key_from_pem(pem: str) -> Ed25519PublicKey:
    return load_pem_public_key(pem.encode())


def sign_payload(priv: Ed25519PrivateKey, payload: dict) -> str:
    """Returns a base64-encoded signature over the canonical payload bytes."""
    sig = priv.sign(canonical_bytes(payload))
    return base64.b64encode(sig).decode()


def verify_payload(pub: Ed25519PublicKey, payload: dict, signature_b64: str) -> bool:
    try:
        pub.verify(base64.b64decode(signature_b64), canonical_bytes(payload))
        return True
    except (InvalidSignature, ValueError):
        return False


if __name__ == "__main__":
    # quick self-test
    priv, pub = new_keypair()
    payload = {"offer_id": "VCH-TEST01", "role": "Software Engineer", "pdf_sha256": "abc123"}
    sig = sign_payload(priv, payload)
    assert verify_payload(pub, payload, sig) is True
    tampered = dict(payload, role="CEO")
    assert verify_payload(pub, tampered, sig) is False
    print("crypto_utils self-test passed")
