# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Load cosign-compatible private and public keys."""

from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_pem_private_key,
    load_pem_public_key,
)
from nacl.secret import SecretBox

_ENCRYPTED_KEY_TYPES = (
    "ENCRYPTED SIGSTORE PRIVATE KEY",
    "ENCRYPTED COSIGN PRIVATE KEY",
)

_ECDSA_CURVE_ALGORITHM_NAMES = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
    "secp256k1": "SECP256K1",
}


def _read_key_material(key_ref: str) -> bytes:
    if key_ref.startswith("-----BEGIN"):
        return key_ref.encode("utf-8")
    path = Path(key_ref)
    if path.is_file():
        return path.read_bytes()
    msg = f"failed to load key from reference: {key_ref}"
    raise ValueError(msg)


def _decrypt_cosign_envelope(envelope_bytes: bytes, password: bytes) -> bytes:
    envelope = json.loads(envelope_bytes)
    if envelope.get("kdf", {}).get("name") != "scrypt":
        msg = "unsupported KDF in encrypted cosign key"
        raise ValueError(msg)
    if envelope.get("cipher", {}).get("name") != "nacl/secretbox":
        msg = "unsupported cipher in encrypted cosign key"
        raise ValueError(msg)

    params = envelope["kdf"]["params"]
    salt = base64.b64decode(envelope["kdf"]["salt"])
    nonce = base64.b64decode(envelope["cipher"]["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=int(params["N"]),
        r=int(params["r"]),
        p=int(params["p"]),
    )
    key = kdf.derive(password)
    return SecretBox(key).decrypt(ciphertext, nonce)


def load_private_key(key_ref: str, password: bytes | None = None) -> PrivateKeyTypes:
    key_bytes = _read_key_material(key_ref)
    password_bytes = (
        password
        if password is not None
        else os.environ.get("COSIGN_PASSWORD", "").encode("utf-8")
    )

    try:
        return load_pem_private_key(
            key_bytes,
            password=password_bytes or None,
        )
    except (TypeError, ValueError):
        pass

    match = re.search(
        rb"-----BEGIN (?:ENCRYPTED SIGSTORE|ENCRYPTED COSIGN) PRIVATE KEY-----\s*(.+?)\s*-----END",
        key_bytes,
        re.DOTALL,
    )
    if match is None:
        msg = f"failed to load private key from reference: {key_ref}"
        raise ValueError(msg)

    envelope_b64 = b"".join(match.group(1).split())
    decrypted = _decrypt_cosign_envelope(base64.b64decode(envelope_b64), password_bytes)
    if decrypted.startswith(b"-----BEGIN"):
        return load_pem_private_key(decrypted, password=None)
    return load_der_private_key(decrypted, password=None)


def load_public_key(key_ref: str) -> bytes:
    key_bytes = _read_key_material(key_ref)
    public_key = load_pem_public_key(key_bytes)
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def detect_key_algorithm(public_key_pem: str | bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric import ec

    pem = (
        public_key_pem
        if isinstance(public_key_pem, bytes)
        else public_key_pem.encode("utf-8")
    )
    try:
        pub_key = load_pem_public_key(pem)
    except ValueError:
        return "unknown"

    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        curve = pub_key.curve.name if pub_key.curve is not None else ""
        curve_name = _ECDSA_CURVE_ALGORITHM_NAMES.get(curve, curve.upper())
        return f"ECDSA-{curve_name}" if curve_name else "ECDSA"
    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pub_key, rsa.RSAPublicKey):
        return f"RSA-{pub_key.key_size}"
    return "unknown"
