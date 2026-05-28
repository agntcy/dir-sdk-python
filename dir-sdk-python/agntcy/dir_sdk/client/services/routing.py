# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Routing service wrappers."""

from __future__ import annotations

from collections.abc import Sequence

from agntcy.dir_sdk.client.services.base import RpcServiceBase
from agntcy.dir_sdk.models import routing_v1


class RoutingService(RpcServiceBase):
    def __init__(self, routing_client: routing_v1.RoutingServiceStub, logger) -> None:
        super().__init__(logger)
        self._routing_client = routing_client

    def publish(
        self,
        req: routing_v1.PublishRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> None:
        self._invoke(
            "publish",
            "Failed to publish object",
            lambda: self._routing_client.Publish(req, metadata=metadata),
        )

    def list(
        self,
        req: routing_v1.ListRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> list[routing_v1.ListResponse]:
        return self._collect_stream(
            "list",
            "Failed to list objects",
            lambda: self._routing_client.List(req, metadata=metadata),
        )

    def unpublish(
        self,
        req: routing_v1.UnpublishRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> None:
        self._invoke(
            "unpublish",
            "Failed to unpublish object",
            lambda: self._routing_client.Unpublish(req, metadata=metadata),
        )
