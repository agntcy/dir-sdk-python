# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""AI Finder service wrappers."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from agntcy.dir_sdk.client.services.base import RpcServiceBase
from agntcy.dir_sdk.models import catalog_v1
from google.api.httpbody_pb2 import HttpBody


class AIFinderService(RpcServiceBase):
    def __init__(
        self,
        ai_finder_client: catalog_v1.AIFinderServiceStub,
        logger: logging.Logger,
    ) -> None:
        super().__init__(logger)
        self._ai_finder_client = ai_finder_client

    def list_agents(
        self,
        req: catalog_v1.ListAgentsRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> catalog_v1.ListAgentsResponse:
        return self._invoke(
            "list_agents",
            "Failed to list agents",
            lambda: self._ai_finder_client.ListAgents(req, metadata=metadata),
        )

    def get_agent(
        self,
        req: catalog_v1.GetAgentRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> catalog_v1.GetAgentResponse:
        return self._invoke(
            "get_agent",
            "Failed to get agent",
            lambda: self._ai_finder_client.GetAgent(req, metadata=metadata),
        )

    def export_agent(
        self,
        req: catalog_v1.ExportAgentRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> HttpBody:
        return self._invoke(
            "export_agent",
            "Failed to export agent",
            lambda: self._ai_finder_client.ExportAgent(req, metadata=metadata),
        )

    def get_well_known_catalog(
        self,
        req: catalog_v1.GetWellKnownCatalogRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> catalog_v1.GetWellKnownCatalogResponse:
        return self._invoke(
            "get_well_known_catalog",
            "Failed to get well-known catalog",
            lambda: self._ai_finder_client.GetWellKnownCatalog(req, metadata=metadata),
        )
