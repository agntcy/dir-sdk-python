# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Verification helpers for dirctl-backed signature validation."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile

from agntcy.dir_sdk.client.config import Config
from agntcy.dir_sdk.client.dirctl.runner import run_dirctl
from agntcy.dir_sdk.models import core_v1, sign_v1
from google.protobuf import json_format


def verify_record(config: Config, req: sign_v1.VerifyRequest) -> sign_v1.VerifyResponse:
    if req.record_ref is None or not req.record_ref.cid:
        msg = "VerifyRequest.record_ref with cid is required"
        raise RuntimeError(msg)

    fd, output_path = tempfile.mkstemp(suffix=".json", prefix="dirctl-verify-")
    os.close(fd)
    try:
        _run_verify(config, req, output_path)
        return parse_verify_response(output_path)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(output_path)


def _run_verify(config: Config, req: sign_v1.VerifyRequest, output_path: str) -> None:
    extra_mounts: list[str] = []
    effective_output_path = output_path
    if config.docker_config:
        basename = os.path.basename(output_path)
        extra_mounts.append(f"type=bind,src={output_path},dst=/{basename}")
        effective_output_path = f"/{basename}"

    provider = req.provider

    if provider.HasField("key"):
        _verify_with_key(
            config,
            req.record_ref,
            provider.key,
            effective_output_path,
            extra_mounts=extra_mounts,
        )
    elif provider.HasField("oidc"):
        _verify_with_oidc(
            config,
            req.record_ref,
            provider.oidc,
            effective_output_path,
            extra_mounts=extra_mounts,
        )
    elif provider.HasField("any"):
        _verify_with_any(
            config,
            req.record_ref,
            provider.any,
            effective_output_path,
            extra_mounts=extra_mounts,
        )
    else:
        msg = "Unsupported verification provider in request"
        raise RuntimeError(msg)


def _verify_with_key(
    config: Config,
    record_ref: core_v1.RecordRef,
    key_verifier: sign_v1.VerifyWithKey,
    output_path: str,
    *,
    extra_mounts: list[str],
) -> None:
    run_dirctl(
        config,
        [
            "verify",
            record_ref.cid,
            "--key",
            key_verifier.public_key,
            "--output-file",
            output_path,
        ],
        extra_mounts=extra_mounts,
        env={"DIRECTORY_CLIENT_SERVER_ADDRESS": config.server_address},
    )


def _verify_with_any(
    config: Config,
    record_ref: core_v1.RecordRef,
    any_verifier: sign_v1.VerifyWithAny | None,
    output_path: str,
    *,
    extra_mounts: list[str],
) -> None:
    command = ["verify", record_ref.cid, "--output-file", output_path]
    if any_verifier is not None and any_verifier.HasField("oidc_options"):
        opts = any_verifier.oidc_options
        if opts.tuf_mirror_url:
            command.extend(["--tuf-mirror-url", opts.tuf_mirror_url])
        if opts.trusted_root_path:
            command.extend(["--trusted-root-path", opts.trusted_root_path])
        if opts.ignore_tlog:
            command.append("--ignore-tlog")
        if opts.ignore_tsa:
            command.append("--ignore-tsa")
        if opts.ignore_sct:
            command.append("--ignore-sct")
    run_dirctl(
        config,
        command,
        extra_mounts=extra_mounts,
        env={"DIRECTORY_CLIENT_SERVER_ADDRESS": config.server_address},
    )


def _verify_with_oidc(
    config: Config,
    record_ref: core_v1.RecordRef,
    oidc_verifier: sign_v1.VerifyWithOIDC | None,
    output_path: str,
    *,
    extra_mounts: list[str],
) -> None:
    command = ["verify", record_ref.cid, "--output-file", output_path]
    if oidc_verifier is not None:
        if oidc_verifier.issuer:
            command.extend(["--oidc-issuer", oidc_verifier.issuer])
        if oidc_verifier.subject:
            command.extend(["--oidc-subject", oidc_verifier.subject])
        if oidc_verifier.HasField("options"):
            opts = oidc_verifier.options
            if opts.tuf_mirror_url:
                command.extend(["--tuf-mirror-url", opts.tuf_mirror_url])
            if opts.trusted_root_path:
                command.extend(["--trusted-root-path", opts.trusted_root_path])
            if opts.ignore_tlog:
                command.append("--ignore-tlog")
            if opts.ignore_tsa:
                command.append("--ignore-tsa")
            if opts.ignore_sct:
                command.append("--ignore-sct")
    run_dirctl(
        config,
        command,
        extra_mounts=extra_mounts,
        env={"DIRECTORY_CLIENT_SERVER_ADDRESS": config.server_address},
    )


def parse_verify_response(output_path: str) -> sign_v1.VerifyResponse:
    try:
        with open(output_path, "rb") as f:
            output = f.read().decode("utf-8")

        json_data = json.loads(output)
        response = sign_v1.VerifyResponse()
        json_format.ParseDict(json_data, response)

        return response
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        msg = f"Failed to parse verification response: {e}"
        raise RuntimeError(msg) from e
