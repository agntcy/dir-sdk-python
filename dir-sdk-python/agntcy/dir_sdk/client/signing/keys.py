# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Key-based signing and verification compatible with cosign key material.

Mirrors the Go client behavior (``client/utils/cosign``):

* private keys are loaded as raw PEM first (cosign encrypted keys or plain
  PKCS#8/PKCS#1/SEC1 PEM) and then as a key reference (file path);
* ECDSA and RSA keys sign/verify with SHA-256 (ASN.1 DER ECDSA, PKCS#1 v1.5 RSA);
* Ed25519 keys sign as Ed25519ph (cosign's default load options) and verify as
  pure Ed25519 first, falling back to Ed25519ph.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os

from agntcy.dir_sdk.client.signing import ed25519ph
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox

PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey
PublicKey = ec.EllipticCurvePublicKey | rsa.RSAPublicKey | ed25519.Ed25519PublicKey

# PEM block types used by cosign for password-protected private keys.
_ENCRYPTED_PEM_TYPES = (
    "ENCRYPTED SIGSTORE PRIVATE KEY",
    "ENCRYPTED COSIGN PRIVATE KEY",
)
_PEM_PREFIX = "-----BEGIN "
_SCRYPT_MAX_MEM = 512 * 1024 * 1024
_CURVE_NAMES = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
}


class KeyLoadError(Exception):
    """Raised when key material cannot be loaded or used."""


def _decrypt_cosign_key(der: bytes, password: bytes) -> bytes:
    try:
        envelope = json.loads(der)
        kdf = envelope["kdf"]
        cipher = envelope["cipher"]
        if kdf["name"] != "scrypt":
            msg = f"unsupported KDF {kdf['name']!r}"
            raise KeyLoadError(msg)
        if cipher["name"] != "nacl/secretbox":
            msg = f"unsupported cipher {cipher['name']!r}"
            raise KeyLoadError(msg)
        params = kdf["params"]
        salt = base64.b64decode(kdf["salt"])
        nonce = base64.b64decode(cipher["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        key = hashlib.scrypt(
            password,
            salt=salt,
            n=int(params["N"]),
            r=int(params["r"]),
            p=int(params["p"]),
            maxmem=_SCRYPT_MAX_MEM,
            dklen=32,
        )
    except (KeyError, TypeError, ValueError, binascii.Error) as e:
        msg = f"invalid encrypted key format: {e}"
        raise KeyLoadError(msg) from e

    try:
        return SecretBox(key).decrypt(ciphertext, nonce)
    except (CryptoError, ValueError) as e:
        msg = "decrypt: wrong password or corrupted key"
        raise KeyLoadError(msg) from e


def _load_private_key_pem(data: bytes, password: bytes) -> PrivateKey:
    text = data.decode("utf-8", errors="ignore")
    for pem_type in _ENCRYPTED_PEM_TYPES:
        if f"{_PEM_PREFIX}{pem_type}-----" in text:
            body = "".join(
                line
                for line in text.splitlines()
                if line and not line.startswith("-----")
            )
            try:
                der = base64.b64decode(body)
            except binascii.Error as e:
                msg = f"invalid PEM body: {e}"
                raise KeyLoadError(msg) from e
            pkcs8 = _decrypt_cosign_key(der, password)
            key = serialization.load_der_private_key(pkcs8, None)
            return _ensure_supported_private(key)

    try:
        key = serialization.load_pem_private_key(data, password or None)
    except (ValueError, TypeError) as e:
        msg = f"unsupported private key: {e}"
        raise KeyLoadError(msg) from e
    return _ensure_supported_private(key)


def _ensure_supported_private(key: object) -> PrivateKey:
    if isinstance(
        key, ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey
    ):
        return key
    msg = f"unsupported private key type: {type(key).__name__}"
    raise KeyLoadError(msg)


def _ensure_supported_public(key: object) -> PublicKey:
    if isinstance(
        key, ec.EllipticCurvePublicKey | rsa.RSAPublicKey | ed25519.Ed25519PublicKey
    ):
        return key
    msg = f"unsupported public key type: {type(key).__name__}"
    raise KeyLoadError(msg)


def _read_key_ref(ref: str) -> bytes:
    if ref.startswith(_PEM_PREFIX):
        msg = "invalid PEM content"
        raise KeyLoadError(msg)
    path = os.path.expanduser(ref)
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        msg = f"unsupported key reference {ref!r}: {e}"
        raise KeyLoadError(msg) from e


def load_private_key(private_key: str, password: bytes = b"") -> PrivateKey:
    """Load a private key from raw PEM content or a key reference (file path)."""
    try:
        return _load_private_key_pem(private_key.encode("utf-8"), password)
    except KeyLoadError as raw_err:
        if private_key.lstrip().startswith(_PEM_PREFIX):
            raise
        try:
            data = _read_key_ref(private_key)
        except KeyLoadError:
            raise raw_err from None
        return _load_private_key_pem(data, password)


def load_public_key(public_key: str) -> PublicKey:
    """Load a public key from raw PEM content or a key reference (file path)."""
    try:
        return _ensure_supported_public(
            serialization.load_pem_public_key(public_key.encode("utf-8"))
        )
    except (ValueError, TypeError, KeyLoadError) as raw_err:
        if public_key.lstrip().startswith(_PEM_PREFIX):
            msg = f"failed to load public key: {raw_err}"
            raise KeyLoadError(msg) from raw_err
        data = _read_key_ref(public_key)
        try:
            return _ensure_supported_public(serialization.load_pem_public_key(data))
        except (ValueError, TypeError) as e:
            msg = f"failed to load public key: {e}"
            raise KeyLoadError(msg) from e


def public_key_pem(key: PrivateKey | PublicKey) -> str:
    """Return the PKIX PEM encoding of the (public part of the) key."""
    pub: PublicKey = (
        key
        if isinstance(
            key,
            ec.EllipticCurvePublicKey | rsa.RSAPublicKey | ed25519.Ed25519PublicKey,
        )
        else key.public_key()
    )
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def sign_message(key: PrivateKey, payload: bytes) -> bytes:
    """Sign payload the same way cosign's default signer/verifier would."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(payload, ec.ECDSA(hashes.SHA256()))
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    seed = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return ed25519ph.sign(seed, payload)


def verify_message(key: PublicKey, signature: bytes, payload: bytes) -> bool:
    """Verify signature over payload; Ed25519 falls back to Ed25519ph."""
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        else:
            try:
                key.verify(signature, payload)
            except InvalidSignature:
                raw = key.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
                return ed25519ph.verify(raw, payload, signature)
    except InvalidSignature:
        return False
    return True


def detect_key_algorithm(public_key_pem_str: str) -> str:
    """Return e.g. ECDSA-P-256, Ed25519 or RSA-2048 for a PEM public key."""
    try:
        key = serialization.load_pem_public_key(public_key_pem_str.encode("utf-8"))
    except (ValueError, TypeError):
        return "unknown"
    if isinstance(key, ec.EllipticCurvePublicKey):
        name = _CURVE_NAMES.get(key.curve.name)
        return f"ECDSA-{name}" if name else "ECDSA"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA-{key.key_size}"
    return "unknown"
