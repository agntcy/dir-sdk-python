# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Default sign and verify option helpers."""

from __future__ import annotations

from agntcy.dir_sdk.models import sign_v1

DEFAULT_FULCIO_URL = "https://fulcio.sigstore.dev"
DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
DEFAULT_TIMESTAMP_URL = "https://timestamp.sigstore.dev/api/v1/timestamp"
DEFAULT_TUF_MIRROR_URL = "https://tuf-repo-cdn.sigstore.dev"
DEFAULT_OIDC_PROVIDER_URL = "https://oauth2.sigstore.dev/auth"
DEFAULT_OIDC_CLIENT_ID = "sigstore"


def get_sign_options_oidc(
    options: sign_v1.SignOptionsOIDC | None,
) -> sign_v1.SignOptionsOIDC:
    if options is None:
        return sign_v1.SignOptionsOIDC(
            fulcio_url=DEFAULT_FULCIO_URL,
            rekor_url=DEFAULT_REKOR_URL,
            timestamp_url=DEFAULT_TIMESTAMP_URL,
            oidc_provider_url=DEFAULT_OIDC_PROVIDER_URL,
            oidc_client_id=DEFAULT_OIDC_CLIENT_ID,
        )
    return sign_v1.SignOptionsOIDC(
        fulcio_url=options.fulcio_url or DEFAULT_FULCIO_URL,
        rekor_url=options.rekor_url or DEFAULT_REKOR_URL,
        timestamp_url=options.timestamp_url or DEFAULT_TIMESTAMP_URL,
        skip_tlog=options.skip_tlog,
        oidc_provider_url=options.oidc_provider_url or DEFAULT_OIDC_PROVIDER_URL,
        oidc_client_id=options.oidc_client_id or DEFAULT_OIDC_CLIENT_ID,
        oidc_client_secret=options.oidc_client_secret,
    )


def get_verify_options_oidc(
    options: sign_v1.VerifyOptionsOIDC | None,
) -> sign_v1.VerifyOptionsOIDC:
    if options is None:
        return sign_v1.VerifyOptionsOIDC(
            tuf_mirror_url=DEFAULT_TUF_MIRROR_URL,
        )
    return sign_v1.VerifyOptionsOIDC(
        tuf_mirror_url=options.tuf_mirror_url or DEFAULT_TUF_MIRROR_URL,
        trusted_root_path=options.trusted_root_path,
        ignore_tlog=options.ignore_tlog,
        ignore_tsa=options.ignore_tsa,
        ignore_sct=options.ignore_sct,
    )
