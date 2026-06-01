# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Publication service wrappers."""

from __future__ import annotations

from collections.abc import Sequence

from agntcy.dir_sdk.client.services.base import RpcServiceBase
from agntcy.dir_sdk.models import routing_v1


class PublicationService(RpcServiceBase):
    def __init__(
        self,
        publication_client: routing_v1.PublicationServiceStub,
        logger,
    ) -> None:
        super().__init__(logger)
        self._publication_client = publication_client

    def create_publication(
        self,
        req: routing_v1.PublishRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> routing_v1.CreatePublicationResponse:
        return self._invoke(
            "create_publication",
            "Failed to create publication",
            lambda: self._publication_client.CreatePublication(req, metadata=metadata),
        )

    def get_publication(
        self,
        req: routing_v1.GetPublicationRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> routing_v1.GetPublicationResponse:
        return self._invoke(
            "get_publication",
            "Failed to get publication",
            lambda: self._publication_client.GetPublication(req, metadata=metadata),
        )

    def list_publication(
        self,
        req: routing_v1.ListPublicationsRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> list[routing_v1.ListPublicationsItem]:
        return self._collect_stream(
            "list_publication",
            "Failed to list publication",
            lambda: self._publication_client.ListPublications(req, metadata=metadata),
        )
