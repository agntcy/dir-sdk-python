# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Native record verification (VerifyWithFetcher semantics of the Go client)."""

from __future__ import annotations

import base64
import logging
from collections.abc import Sequence

from agntcy.dir_sdk.client.services.store import StoreService
from agntcy.dir_sdk.client.signing import keys, oidc, referrer
from agntcy.dir_sdk.models import core_v1, sign_v1, store_v1

logger = logging.getLogger("client")

_RECORD_NOT_FOUND = "record not found"


def pull_signatures(
    store_service: StoreService,
    record_ref: core_v1.RecordRef,
    metadata: Sequence[tuple[str, str]] | None = None,
) -> list[sign_v1.Signature]:
    """Fetch all signature referrers for a record."""
    responses = store_service.pull_referrer(
        [
            store_v1.PullReferrerRequest(
                record_ref=record_ref,
                referrer_type=referrer.SIGNATURE_REFERRER_TYPE,
            )
        ],
        metadata=metadata,
    )
    signatures: list[sign_v1.Signature] = []
    for response in responses:
        if not response.HasField("referrer"):
            continue
        try:
            signatures.append(referrer.unmarshal_signature(response.referrer))
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to unmarshal signature referrer: %s", e)
    return signatures


def pull_public_keys(
    store_service: StoreService,
    record_ref: core_v1.RecordRef,
    metadata: Sequence[tuple[str, str]] | None = None,
) -> list[str]:
    """Fetch all public key referrers for a record."""
    responses = store_service.pull_referrer(
        [
            store_v1.PullReferrerRequest(
                record_ref=record_ref,
                referrer_type=referrer.PUBLIC_KEY_REFERRER_TYPE,
            )
        ],
        metadata=metadata,
    )
    public_keys: list[str] = []
    for response in responses:
        if not response.HasField("referrer"):
            continue
        try:
            public_key = referrer.unmarshal_public_key(response.referrer)
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to unmarshal public key referrer: %s", e)
            continue
        if public_key.key:
            public_keys.append(public_key.key)
    return public_keys


def _failure(message: str) -> sign_v1.VerifyResponse:
    return sign_v1.VerifyResponse(success=False, error_message=message)


def _is_record_not_found(error: Exception) -> bool:
    if _RECORD_NOT_FOUND in str(error):
        return True
    details = getattr(error, "details", None)
    return callable(details) and _RECORD_NOT_FOUND in str(details())


def verify_record(
    store_service: StoreService,
    req: sign_v1.VerifyRequest,
    metadata: Sequence[tuple[str, str]] | None = None,
) -> sign_v1.VerifyResponse:
    """Verify record signatures locally against the signatures held in the store."""
    if not req.HasField("record_ref") or not req.record_ref.cid:
        msg = "record CID is required"
        raise ValueError(msg)

    try:
        store_service.lookup([req.record_ref], metadata=metadata)
    except Exception as e:
        if _is_record_not_found(e):
            return _failure(_RECORD_NOT_FOUND)
        msg = f"failed to lookup record: {e}"
        raise RuntimeError(msg) from e

    return verify_with_fetcher(store_service, req, metadata=metadata)


def _verify_with_keys(
    payload: bytes,
    public_keys: Sequence[str],
    signature: sign_v1.Signature,
) -> sign_v1.SignerInfo:
    """Try every public key against the signature; first match wins."""
    for public_key in public_keys:
        try:
            key = keys.load_public_key(public_key)
        except keys.KeyLoadError:
            continue
        try:
            raw_signature = base64.b64decode(signature.signature, validate=True)
        except ValueError:
            # If decoding fails, assume it's already raw bytes.
            raw_signature = signature.signature.encode("utf-8")
        if not keys.verify_message(key, raw_signature, payload):
            continue
        pem = keys.public_key_pem(key)
        return sign_v1.SignerInfo(
            key=sign_v1.SignerInfoKey(
                public_key=pem,
                algorithm=keys.detect_key_algorithm(pem),
            )
        )
    msg = "no valid signature found for the provided public keys"
    raise ValueError(msg)


def _verify_with_any(
    payload: bytes,
    public_keys: Sequence[str],
    signature: sign_v1.Signature,
    oidc_options: sign_v1.VerifyOptionsOIDC,
) -> sign_v1.SignerInfo:
    if not signature.content_bundle:
        try:
            return _verify_with_keys(payload, public_keys, signature)
        except ValueError as e:
            msg = f"failed to verify signature with keys: {e}"
            raise ValueError(msg) from e
    try:
        return oidc.verify_with_oidc(
            payload, sign_v1.VerifyWithOIDC(options=oidc_options), signature
        )
    except oidc.OIDCError as e:
        msg = f"failed to verify signature with OIDC: {e}"
        raise ValueError(msg) from e


def _signer_key(signer: sign_v1.SignerInfo) -> str:
    kind = signer.WhichOneof("type")
    if kind == "key":
        return f"key:{signer.key.SerializeToString(deterministic=True).hex()}"
    if kind == "oidc":
        return f"oidc:{signer.oidc.SerializeToString(deterministic=True).hex()}"
    return ""


def verify_with_fetcher(
    store_service: StoreService,
    req: sign_v1.VerifyRequest,
    metadata: Sequence[tuple[str, str]] | None = None,
) -> sign_v1.VerifyResponse:
    """Verify all signatures of a record according to the request provider."""
    if not req.HasField("record_ref") or not req.record_ref.cid:
        msg = "record ref is required"
        raise ValueError(msg)

    provider_kind = (
        req.provider.WhichOneof("request") if req.HasField("provider") else None
    )
    if provider_kind is None:
        # Default provider: any signer, default OIDC options.
        provider = sign_v1.VerifyRequestProvider(any=sign_v1.VerifyWithAny())
        provider_kind = "any"
    else:
        provider = req.provider

    try:
        signatures = pull_signatures(store_service, req.record_ref, metadata)
    except Exception as e:
        msg = f"pull signatures: {e}"
        raise RuntimeError(msg) from e

    if not signatures:
        return _failure("no signatures found")

    public_keys: list[str] = []
    if provider_kind == "key":
        public_keys = [provider.key.public_key]
    elif provider_kind == "any":
        try:
            public_keys = pull_public_keys(store_service, req.record_ref, metadata)
        except Exception as e:
            msg = f"pull public keys: {e}"
            raise RuntimeError(msg) from e

    payload = req.record_ref.cid.encode("utf-8")
    oidc_options = (
        provider.any.oidc_options
        if provider_kind == "any" and provider.any.HasField("oidc_options")
        else sign_v1.VerifyOptionsOIDC()
    )

    seen_keys: set[str] = set()
    signers: list[sign_v1.SignerInfo] = []
    for signature in signatures:
        try:
            if provider_kind == "oidc":
                signer_info = oidc.verify_with_oidc(payload, provider.oidc, signature)
            elif provider_kind == "key":
                signer_info = _verify_with_keys(payload, public_keys, signature)
            else:
                signer_info = _verify_with_any(
                    payload, public_keys, signature, oidc_options
                )
        except Exception as e:  # noqa: BLE001
            # Failed verifications have no SignerInfo; only verified signers are reported.
            logger.debug("Signature verification failed: %s", e)
            continue

        signer_key = _signer_key(signer_info)
        if signer_key in seen_keys:
            continue  # Only report one result per signer
        seen_keys.add(signer_key)
        signers.append(signer_info)

    if not signers:
        return _failure("no valid signatures found matching verification criteria")

    return sign_v1.VerifyResponse(success=True, signers=signers)
