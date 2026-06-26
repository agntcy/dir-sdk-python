# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""OIDC / Sigstore signing for Directory records."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

from agntcy.dir_sdk.client.signing.options import get_sign_options_oidc
from agntcy.dir_sdk.models import sign_v1
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sigstore._internal.fulcio.client import FulcioClient
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.timestamp import TimestampAuthorityClient
from sigstore.models import ClientTrustConfig
from sigstore.oidc import IdentityToken
from sigstore.sign import SigningContext


def _tuf_url_for_provider(oidc_provider_url: str) -> str:
    if "sigstage" in oidc_provider_url:
        return "https://tuf-repo-cdn.sigstage.dev"
    return "https://tuf-repo-cdn.sigstore.dev"


def sign_with_oidc(
    cid: str, req: sign_v1.SignWithOIDC
) -> tuple[sign_v1.Signature, sign_v1.PublicKey]:
    opts = get_sign_options_oidc(req.options)
    identity_token = IdentityToken(
        req.id_token, client_id=opts.oidc_client_id or "sigstore"
    )
    payload = cid.encode("utf-8")

    trust_config = ClientTrustConfig.from_tuf(
        _tuf_url_for_provider(opts.oidc_provider_url),
        offline=False,
    )
    signing_ctx = SigningContext(
        fulcio=FulcioClient(url=opts.fulcio_url),
        rekor=RekorClient(url=opts.rekor_url),
        trusted_root=trust_config.trusted_root,
        tsa_clients=(
            [TimestampAuthorityClient(url=opts.timestamp_url)]
            if opts.timestamp_url
            else []
        ),
    )

    with signing_ctx.signer(identity_token, cache=False) as signer:
        bundle = signer.sign_artifact(payload)

    cert_der = bundle.signing_certificate.public_bytes(encoding=Encoding.DER)
    public_key_pem = (
        bundle.signing_certificate.public_key()
        .public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    return (
        sign_v1.Signature(
            signature=base64.b64encode(bundle.signature).decode("ascii"),
            certificate=base64.b64encode(cert_der).decode("ascii"),
            content_type=bundle._inner.media_type,
            content_bundle=bundle.to_json(),
            signed_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
        sign_v1.PublicKey(key=public_key_pem),
    )
