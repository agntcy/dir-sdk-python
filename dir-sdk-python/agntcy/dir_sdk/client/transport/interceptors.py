# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Authentication interceptors for gRPC client channels."""

from __future__ import annotations

from collections.abc import Callable

import grpc
from spiffe import WorkloadApiClient


def _build_call_details(client_call_details, metadata: list[tuple[str, str]]):
    return grpc._interceptor._ClientCallDetails(
        method=client_call_details.method,
        timeout=client_call_details.timeout,
        metadata=metadata,
        credentials=client_call_details.credentials,
        wait_for_ready=client_call_details.wait_for_ready,
        compression=client_call_details.compression,
    )


class JWTAuthInterceptor(
    grpc.UnaryUnaryClientInterceptor,
    grpc.UnaryStreamClientInterceptor,
    grpc.StreamUnaryClientInterceptor,
    grpc.StreamStreamClientInterceptor,
):
    """Add SPIFFE JWT-SVID authorization metadata to outgoing requests."""

    def __init__(self, socket_path: str, audience: str) -> None:
        self._audience = audience
        self._workload_client = WorkloadApiClient(socket_path=socket_path)

    def _get_jwt_token(self) -> str:
        try:
            jwt_svid = self._workload_client.fetch_jwt_svid(audience=[self._audience])
            if jwt_svid and jwt_svid.token:
                return jwt_svid.token
            msg = "Failed to fetch JWT-SVID: empty token"
            raise RuntimeError(msg)
        except Exception as e:
            msg = f"Failed to fetch JWT-SVID: {e}"
            raise RuntimeError(msg) from e

    def _add_jwt_metadata(self, client_call_details):
        metadata = list(client_call_details.metadata or [])
        metadata.append(("authorization", f"Bearer {self._get_jwt_token()}"))
        return _build_call_details(client_call_details, metadata)

    def intercept_unary_unary(self, continuation, client_call_details, request):
        return continuation(self._add_jwt_metadata(client_call_details), request)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        return continuation(self._add_jwt_metadata(client_call_details), request)

    def intercept_stream_unary(
        self, continuation, client_call_details, request_iterator
    ):
        return continuation(
            self._add_jwt_metadata(client_call_details), request_iterator
        )

    def intercept_stream_stream(
        self, continuation, client_call_details, request_iterator
    ):
        return continuation(
            self._add_jwt_metadata(client_call_details), request_iterator
        )


class BearerAuthInterceptor(
    grpc.UnaryUnaryClientInterceptor,
    grpc.UnaryStreamClientInterceptor,
    grpc.StreamUnaryClientInterceptor,
    grpc.StreamStreamClientInterceptor,
):
    """Add static bearer authorization metadata to outgoing requests."""

    def __init__(self, token_supplier: Callable[[], str]) -> None:
        self._token_supplier = token_supplier

    def _add_bearer_metadata(self, client_call_details):
        metadata = list(client_call_details.metadata or [])
        metadata.append(("authorization", f"Bearer {self._token_supplier()}"))
        return _build_call_details(client_call_details, metadata)

    def intercept_unary_unary(self, continuation, client_call_details, request):
        return continuation(self._add_bearer_metadata(client_call_details), request)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        return continuation(self._add_bearer_metadata(client_call_details), request)

    def intercept_stream_unary(
        self, continuation, client_call_details, request_iterator
    ):
        return continuation(
            self._add_bearer_metadata(client_call_details), request_iterator
        )

    def intercept_stream_stream(
        self, continuation, client_call_details, request_iterator
    ):
        return continuation(
            self._add_bearer_metadata(client_call_details), request_iterator
        )
