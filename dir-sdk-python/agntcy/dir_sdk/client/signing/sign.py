# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Native record signing (key and OIDC providers) and referrer publication."""

from __future__ import annotations

import base64
from datetime import datetime, timezone

from agntcy.dir_sdk.client.services.store import StoreService
from agntcy.dir_sdk.client.signing import keys, oidc, referrer
from agntcy.dir_sdk.models import core_v1, sign_v1, store_v1


def sign_blob_with_key(
    payload: bytes,
    req: sign_v1.SignWithKey,
) -> tuple[sign_v1.Signature, sign_v1.PublicKey]:
    """Sign payload with a private key (inline PEM or key reference)."""
    if not req.private_key:
        msg = "private_key is required"
        raise ValueError(msg)

    try:
        private_key = keys.load_private_key(req.private_key, bytes(req.password))
    except keys.KeyLoadError as e:
        msg = f"loading private key from reference: {e}"
        raise ValueError(msg) from e

    raw_signature = keys.sign_message(private_key, payload)
    public_key_pem = keys.public_key_pem(private_key)

    signature = sign_v1.Signature(
        signed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        signature=base64.b64encode(raw_signature).decode("ascii"),
        algorithm=keys.detect_key_algorithm(public_key_pem),
    )
    return signature, sign_v1.PublicKey(key=public_key_pem)


def sign_record(store_service: StoreService, req: sign_v1.SignRequest) -> None:
    """Sign the record CID and push the public key and signature as referrers."""
    provider = req.provider.WhichOneof("request") if req.HasField("provider") else None
    if provider is None:
        msg = "signature provider must be specified"
        raise ValueError(msg)
    if not req.HasField("record_ref") or not req.record_ref.cid:
        msg = "record ref must be specified"
        raise ValueError(msg)

    payload = req.record_ref.cid.encode("utf-8")
    try:
        if provider == "key":
            signature, public_key = sign_blob_with_key(payload, req.provider.key)
        elif provider == "oidc":
            signature, public_key = oidc.sign_blob_with_oidc(payload, req.provider.oidc)
        else:
            msg = f"unsupported signature provider type: {provider}"
            raise ValueError(msg)
    except (ValueError, oidc.OIDCError) as e:
        msg = f"failed to sign record: {e}"
        raise RuntimeError(msg) from e

    _push_referrers_to_store(store_service, req.record_ref, signature, public_key)


def _push_referrers_to_store(
    store_service: StoreService,
    record_ref: core_v1.RecordRef,
    signature: sign_v1.Signature,
    public_key: sign_v1.PublicKey,
) -> None:
    public_key_referrer = referrer.marshal_public_key(public_key)
    try:
        store_service.push_referrer([_push_request(record_ref, public_key_referrer)])
    except Exception as e:
        msg = f"failed to store public key: {e}"
        raise RuntimeError(msg) from e

    signature_referrer = referrer.marshal_signature(signature)
    try:
        store_service.push_referrer([_push_request(record_ref, signature_referrer)])
    except Exception as e:
        msg = f"failed to store signature: {e}"
        raise RuntimeError(msg) from e


def _push_request(
    record_ref: core_v1.RecordRef,
    record_referrer: core_v1.RecordReferrer,
) -> store_v1.PushReferrerRequest:
    return store_v1.PushReferrerRequest(
        record_ref=record_ref,
        type=record_referrer.type,
        annotations=record_referrer.annotations,
        created_at=record_referrer.created_at,
        data=record_referrer.data,
    )
