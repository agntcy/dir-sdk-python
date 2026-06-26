# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Key-based signing for Directory records."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

from agntcy.dir_sdk.client.signing.cosign_keys import (
    detect_key_algorithm,
    load_private_key,
)
from agntcy.dir_sdk.models import sign_v1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _sign_payload(private_key: object, payload: bytes) -> bytes:
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return private_key.sign(payload)
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    msg = "unsupported private key type"
    raise TypeError(msg)


def sign_with_key(
    cid: str, req: sign_v1.SignWithKey
) -> tuple[sign_v1.Signature, sign_v1.PublicKey]:
    password = req.password if req.password else None
    private_key = load_private_key(req.private_key, password)
    payload = cid.encode("utf-8")

    signature_bytes = _sign_payload(private_key, payload)
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    return (
        sign_v1.Signature(
            signed_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            signature=base64.b64encode(signature_bytes).decode("ascii"),
            algorithm=detect_key_algorithm(public_key_pem),
        ),
        sign_v1.PublicKey(key=public_key_pem),
    )
