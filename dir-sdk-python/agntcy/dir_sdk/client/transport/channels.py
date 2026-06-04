# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""gRPC channel factory helpers."""

from __future__ import annotations

from pathlib import Path

import grpc
from agntcy.dir_sdk.client.auth.oauth_pkce import OAuthTokenHolder
from agntcy.dir_sdk.client.config import Config
from agntcy.dir_sdk.client.transport.interceptors import (
    BearerAuthInterceptor,
    JWTAuthInterceptor,
)
from cryptography.hazmat.primitives import serialization
from spiffe import WorkloadApiClient, X509Source


def grpc_channel_options(config: Config) -> list[tuple[str, str]]:
    server_name = config.tls_server_name.strip()
    if not server_name:
        return []
    return [
        ("grpc.ssl_target_name_override", server_name),
        ("grpc.default_authority", server_name),
    ]


def create_grpc_channel(
    config: Config,
    oauth_holder: OAuthTokenHolder | None = None,
) -> grpc.Channel:
    if config.auth_mode == "":
        return grpc.insecure_channel(config.server_address)
    if config.auth_mode == "jwt":
        return create_jwt_channel(config)
    if config.auth_mode == "x509":
        return create_x509_channel(config)
    if config.auth_mode == "tls":
        return create_tls_channel(config)
    if config.auth_mode == "oidc":
        return create_oauth_pkce_channel(config, oauth_holder)
    msg = f"Unsupported auth mode: {config.auth_mode}"
    raise ValueError(msg)


def create_x509_channel(config: Config) -> grpc.Channel:
    if config.spiffe_socket_path == "":
        msg = "SPIFFE socket path is required for X.509 authentication"
        raise ValueError(msg)

    workload_client = WorkloadApiClient(socket_path=config.spiffe_socket_path)
    x509_src = X509Source(
        workload_api_client=workload_client,
        socket_path=config.spiffe_socket_path,
        timeout_in_seconds=60,
    )

    root_ca = b""
    for bundle in x509_src.bundles:
        for authority in bundle.x509_authorities:
            root_ca += authority.public_bytes(encoding=serialization.Encoding.PEM)

    private_key = x509_src.svid.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_leaf = x509_src.svid.leaf.public_bytes(encoding=serialization.Encoding.PEM)

    credentials = grpc.ssl_channel_credentials(
        root_certificates=root_ca,
        private_key=private_key,
        certificate_chain=public_leaf,
    )
    return grpc.secure_channel(
        target=config.server_address,
        credentials=credentials,
        options=grpc_channel_options(config),
    )


def create_jwt_channel(config: Config) -> grpc.Channel:
    if config.spiffe_socket_path == "":
        msg = "SPIFFE socket path is required for JWT authentication"
        raise ValueError(msg)
    if config.jwt_audience == "":
        msg = "JWT audience is required for JWT authentication"
        raise ValueError(msg)

    workload_client = WorkloadApiClient(socket_path=config.spiffe_socket_path)
    x509_source = X509Source(
        workload_api_client=workload_client,
        socket_path=config.spiffe_socket_path,
        timeout_in_seconds=60,
    )
    try:
        root_ca = b""
        for bundle in x509_source.bundles:
            for authority in bundle.x509_authorities:
                root_ca += authority.public_bytes(encoding=serialization.Encoding.PEM)
        if not root_ca:
            msg = "Failed to fetch X.509 bundle from SPIRE: no bundles returned"
            raise RuntimeError(msg)

        credentials = grpc.ssl_channel_credentials(root_certificates=root_ca)
        channel = grpc.secure_channel(
            target=config.server_address,
            credentials=credentials,
            options=grpc_channel_options(config),
        )
    finally:
        x509_source.close()

    jwt_interceptor = JWTAuthInterceptor(
        socket_path=config.spiffe_socket_path,
        audience=config.jwt_audience,
    )
    return grpc.intercept_channel(channel, jwt_interceptor)


def create_tls_channel(config: Config) -> grpc.Channel:
    if not config.tls_ca_file:
        msg = "TLS CA file is required for TLS authentication"
        raise ValueError(msg)
    if not config.tls_cert_file:
        msg = "TLS certificate file is required for TLS authentication"
        raise ValueError(msg)
    if not config.tls_key_file:
        msg = "TLS key file is required for TLS authentication"
        raise ValueError(msg)

    try:
        root_ca = Path(config.tls_ca_file).read_bytes()
        cert_chain = Path(config.tls_cert_file).read_bytes()
        private_key = Path(config.tls_key_file).read_bytes()
    except OSError as e:
        msg = f"Failed to read TLS files: {e}"
        raise RuntimeError(msg) from e

    credentials = grpc.ssl_channel_credentials(
        root_certificates=root_ca,
        private_key=private_key,
        certificate_chain=cert_chain,
    )
    return grpc.secure_channel(
        target=config.server_address,
        credentials=credentials,
        options=grpc_channel_options(config),
    )


def create_oauth_pkce_channel(
    config: Config,
    oauth_holder: OAuthTokenHolder | None,
) -> grpc.Channel:
    if oauth_holder is None:
        msg = "OAuth token holder not initialized"
        raise RuntimeError(msg)

    root_ca = None
    if config.tls_ca_file:
        try:
            root_ca = Path(config.tls_ca_file).read_bytes()
        except OSError as e:
            msg = f"Failed to read TLS CA file: {e}"
            raise RuntimeError(msg) from e

    credentials = grpc.ssl_channel_credentials(root_certificates=root_ca)
    channel = grpc.secure_channel(
        target=config.server_address,
        credentials=credentials,
        options=grpc_channel_options(config),
    )
    bearer = BearerAuthInterceptor(oauth_holder.get_access_token)
    return grpc.intercept_channel(channel, bearer)
