# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Signing helpers for dirctl-backed signature creation."""

from __future__ import annotations

from agntcy.dir_sdk.client.config import Config
from agntcy.dir_sdk.client.dirctl.runner import run_dirctl
from agntcy.dir_sdk.models import core_v1, sign_v1


def sign_record(config: Config, req: sign_v1.SignRequest) -> None:
    if req.provider.HasField("key"):
        _sign_with_key(config, req.record_ref, req.provider.key)
        return
    elif req.provider.HasField("oidc"):
        _sign_with_oidc(config, req.record_ref, req.provider.oidc)
        return
    else:
        msg = "Unsupported signing provider in request"
        raise RuntimeError(msg)


def _sign_with_key(
    config: Config,
    record_ref: core_v1.RecordRef,
    key_signer: sign_v1.SignWithKey,
) -> None:
    password = ""
    if key_signer.password:
        password = key_signer.password.decode("utf-8")
    run_dirctl(
        config,
        ["sign", record_ref.cid, "--key", key_signer.private_key],
        env={"COSIGN_PASSWORD": password,
             "DIRECTORY_CLIENT_SERVER_ADDRESS": config.server_address},
    )


def _sign_with_oidc(
    config: Config,
    record_ref: core_v1.RecordRef,
    oidc_signer: sign_v1.SignWithOIDC,
) -> None:
    command = ["sign", record_ref.cid]
    if oidc_signer.id_token:
        command.extend(["--oidc-token", oidc_signer.id_token])
    if oidc_signer.options.oidc_provider_url:
        command.extend(["--oidc-provider-url", oidc_signer.options.oidc_provider_url])
    if oidc_signer.options.oidc_client_id:
        command.extend(["--oidc-client-id", oidc_signer.options.oidc_client_id])
    if oidc_signer.options.oidc_client_secret:
        command.extend(["--oidc-client-secret", oidc_signer.options.oidc_client_secret])
    if oidc_signer.options.fulcio_url:
        command.extend(["--fulcio-url", oidc_signer.options.fulcio_url])
    if oidc_signer.options.rekor_url:
        command.extend(["--rekor-url", oidc_signer.options.rekor_url])
    if oidc_signer.options.timestamp_url:
        command.extend(["--timestamp-url", oidc_signer.options.timestamp_url])
    if oidc_signer.options.skip_tlog:
        command.append("--skip-tlog")

    run_dirctl(config, command, env={"DIRECTORY_CLIENT_SERVER_ADDRESS": config.server_address})
