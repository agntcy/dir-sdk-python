# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Ed25519ph (RFC 8032, section 5.1) sign and verify backed by libsodium.

Cosign loads Ed25519 private keys as Ed25519ph signers (the message is
pre-hashed with SHA-512 and the dom2 prefix is applied). The `cryptography`
package only exposes pure Ed25519, so the pre-hashed variant is taken from
PyNaCl's libsodium bindings.
"""

from __future__ import annotations

import nacl.bindings as sodium
from nacl.exceptions import BadSignatureError

_SEED_BYTES = sodium.crypto_sign_SEEDBYTES
_PUBLIC_KEY_BYTES = sodium.crypto_sign_PUBLICKEYBYTES
_SIGNATURE_BYTES = sodium.crypto_sign_BYTES


def public_key(seed: bytes) -> bytes:
    """Derive the raw 32-byte public key from a 32-byte private seed."""
    return _keypair(seed)[0]


def _keypair(seed: bytes) -> tuple[bytes, bytes]:
    if len(seed) != _SEED_BYTES:
        msg = "Ed25519 seed must be 32 bytes"
        raise ValueError(msg)
    return sodium.crypto_sign_seed_keypair(seed)


def sign(seed: bytes, message: bytes) -> bytes:
    """Create an Ed25519ph signature over message."""
    _, secret_key = _keypair(seed)
    state = sodium.crypto_sign_ed25519ph_state()
    sodium.crypto_sign_ed25519ph_update(state, message)
    return sodium.crypto_sign_ed25519ph_final_create(state, secret_key)


def verify(pub: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519ph signature over message."""
    if len(pub) != _PUBLIC_KEY_BYTES or len(signature) != _SIGNATURE_BYTES:
        return False
    state = sodium.crypto_sign_ed25519ph_state()
    sodium.crypto_sign_ed25519ph_update(state, message)
    try:
        return bool(sodium.crypto_sign_ed25519ph_final_verify(state, signature, pub))
    except BadSignatureError:
        return False
