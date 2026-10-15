# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Signing and local verification backed by the native wrapper library."""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import Any

from agntcy.dir_sdk.client.config import Config
from agntcy.dir_sdk.client.native.library import NativeLibrary, load_library
from agntcy.dir_sdk.models import sign_v1
from google.protobuf import json_format


def native_client_config(config: Config, auth_token: str = "") -> dict[str, Any]:
    """Translate the SDK config to the Go ``client.Config`` JSON shape."""
    values: dict[str, Any] = {
        "server_address": config.server_address,
        "tls_skip_verify": config.tls_skip_verify,
        "tls_cert_file": config.tls_cert_file,
        "tls_key_file": config.tls_key_file,
        "tls_ca_file": config.tls_ca_file,
        "spiffe_socket_path": config.spiffe_socket_path,
        "auth_mode": config.auth_mode,
        "jwt_audience": config.jwt_audience,
        "oidc_issuer": config.oidc_issuer,
        "oidc_client_id": config.oidc_client_id,
        "oidc_scopes": config.oidc_scopes,
        "auth_token": auth_token or config.auth_token,
    }
    return {k: v for k, v in values.items() if v not in ("", False, None)}


@contextlib.contextmanager
def _native_client(
    lib: NativeLibrary, config: Config, auth_token: str
) -> Iterator[int]:
    handle = lib.call("NewClient", native_client_config(config, auth_token))["handle"]
    try:
        yield handle
    finally:
        lib.call("CloseClient", handle)


def sign_record(config: Config, req: sign_v1.SignRequest, auth_token: str = "") -> None:
    """Sign a record and push the signature and public key to the store."""
    if not req.provider.HasField("key") and not req.provider.HasField("oidc"):
        msg = "Unsupported signing provider in request"
        raise RuntimeError(msg)
    if not req.record_ref.cid:
        msg = "SignRequest.record_ref with cid is required"
        raise RuntimeError(msg)

    lib = load_library()
    payload = json_format.MessageToJson(req)
    with _native_client(lib, config, auth_token) as handle:
        lib.call("Sign", handle, payload)


def verify_record(
    config: Config, req: sign_v1.VerifyRequest, auth_token: str = ""
) -> sign_v1.VerifyResponse:
    """Verify a record locally using the signatures pulled from the store."""
    if not req.record_ref.cid:
        msg = "VerifyRequest.record_ref with cid is required"
        raise RuntimeError(msg)
    if not any(req.provider.HasField(f) for f in ("key", "oidc", "any")):
        msg = "Unsupported verification provider in request"
        raise RuntimeError(msg)

    lib = load_library()
    payload = json_format.MessageToJson(req)
    with _native_client(lib, config, auth_token) as handle:
        response = lib.call("Verify", handle, payload)

    result = sign_v1.VerifyResponse()
    json_format.ParseDict(
        response.get("response", {}), result, ignore_unknown_fields=True
    )
    return result
