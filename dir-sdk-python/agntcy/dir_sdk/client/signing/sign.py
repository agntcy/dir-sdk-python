# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Sign Directory records and push signature referrers."""

from __future__ import annotations

from agntcy.dir_sdk.client.services.store import StoreService
from agntcy.dir_sdk.client.signing.fetcher import StoreFetcher
from agntcy.dir_sdk.client.signing.referrers import (
    marshal_public_key_referrer,
    marshal_signature_referrer,
)
from agntcy.dir_sdk.client.signing.sign_key import sign_with_key
from agntcy.dir_sdk.client.signing.sign_oidc import sign_with_oidc
from agntcy.dir_sdk.models import core_v1, sign_v1, store_v1


def _push_referrers(
    store_service: StoreService,
    record_ref: core_v1.RecordRef,
    signature: sign_v1.Signature,
    public_key: sign_v1.PublicKey,
) -> None:
    public_key_referrer = marshal_public_key_referrer(public_key)
    signature_referrer = marshal_signature_referrer(signature)

    store_service.push_referrer(
        [
            store_v1.PushReferrerRequest(
                record_ref=record_ref,
                type=public_key_referrer.type,
                annotations=public_key_referrer.annotations,
                created_at=public_key_referrer.created_at,
                data=public_key_referrer.data,
            ),
            store_v1.PushReferrerRequest(
                record_ref=record_ref,
                type=signature_referrer.type,
                annotations=signature_referrer.annotations,
                created_at=signature_referrer.created_at,
                data=signature_referrer.data,
            ),
        ]
    )


def sign_record(store_service: StoreService, req: sign_v1.SignRequest) -> None:
    if req.record_ref is None or not req.record_ref.cid:
        msg = "record ref must be specified"
        raise ValueError(msg)
    if req.provider is None:
        msg = "signature provider must be specified"
        raise ValueError(msg)

    StoreFetcher(store_service).lookup(req.record_ref)

    if req.provider.HasField("key"):
        signature, public_key = sign_with_key(req.record_ref.cid, req.provider.key)
    elif req.provider.HasField("oidc"):
        signature, public_key = sign_with_oidc(req.record_ref.cid, req.provider.oidc)
    else:
        msg = "unsupported signature provider type"
        raise ValueError(msg)

    _push_referrers(store_service, req.record_ref, signature, public_key)
