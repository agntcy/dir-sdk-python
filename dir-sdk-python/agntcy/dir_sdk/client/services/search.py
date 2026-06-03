# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Search service wrappers."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from agntcy.dir_sdk.client.services.base import RpcServiceBase
from agntcy.dir_sdk.models import search_v1


class SearchService(RpcServiceBase):
    def __init__(
        self, search_client: search_v1.SearchServiceStub, logger: logging.Logger
    ) -> None:
        super().__init__(logger)
        self._search_client = search_client

    def search_cids(
        self,
        req: search_v1.SearchCIDsRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> list[search_v1.SearchCIDsResponse]:
        return self._collect_stream(
            "search",
            "Failed to search CIDs",
            lambda: self._search_client.SearchCIDs(req, metadata=metadata),
        )

    def search_records(
        self,
        req: search_v1.SearchRecordsRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> list[search_v1.SearchRecordsResponse]:
        return self._collect_stream(
            "search",
            "Failed to search records",
            lambda: self._search_client.SearchRecords(req, metadata=metadata),
        )
