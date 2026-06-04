# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Sync service wrappers."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from agntcy.dir_sdk.client.services.base import RpcServiceBase
from agntcy.dir_sdk.models import store_v1


class SyncService(RpcServiceBase):
    def __init__(
        self, sync_client: store_v1.SyncServiceStub, logger: logging.Logger
    ) -> None:
        super().__init__(logger)
        self._sync_client = sync_client

    def create_sync(
        self,
        req: store_v1.CreateSyncRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> store_v1.CreateSyncResponse:
        return self._invoke(
            "create_sync",
            "Failed to create sync",
            lambda: self._sync_client.CreateSync(req, metadata=metadata),
        )

    def list_syncs(
        self,
        req: store_v1.ListSyncsRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> list[store_v1.ListSyncsItem]:
        return self._collect_stream(
            "list_syncs",
            "Failed to list syncs",
            lambda: self._sync_client.ListSyncs(req, metadata=metadata),
        )

    def get_sync(
        self,
        req: store_v1.GetSyncRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> store_v1.GetSyncResponse:
        return self._invoke(
            "get_sync",
            "Failed to get sync",
            lambda: self._sync_client.GetSync(req, metadata=metadata),
        )

    def delete_sync(
        self,
        req: store_v1.DeleteSyncRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> None:
        self._invoke(
            "delete_sync",
            "Failed to delete sync",
            lambda: self._sync_client.DeleteSync(req, metadata=metadata),
        )
