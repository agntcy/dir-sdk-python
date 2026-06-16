# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Store service wrappers."""

from __future__ import annotations

import builtins
import logging
from collections.abc import Iterator, Sequence

from agntcy.dir_sdk.client.services.base import RpcServiceBase
from agntcy.dir_sdk.models import core_v1, store_v1


class StoreService(RpcServiceBase):
    def __init__(
        self, store_client: store_v1.StoreServiceStub, logger: logging.Logger
    ) -> None:
        super().__init__(logger)
        self._store_client = store_client

    def push(
        self,
        records: builtins.list[core_v1.Record],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> builtins.list[core_v1.RecordRef]:
        return self._collect_stream(
            "push",
            "Failed to push object",
            lambda: self._store_client.Push(iter(records), metadata=metadata),
        )

    def push_referrer(
        self,
        req: builtins.list[store_v1.PushReferrerRequest],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> builtins.list[store_v1.PushReferrerResponse]:
        return self._collect_stream(
            "push_referrer",
            "Failed to push object",
            lambda: self._store_client.PushReferrer(iter(req), metadata=metadata),
        )

    def pull(
        self,
        refs: builtins.list[core_v1.RecordRef],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> builtins.list[core_v1.Record]:
        return self._collect_stream(
            "pull",
            "Failed to pull object",
            lambda: self._store_client.Pull(iter(refs), metadata=metadata),
        )

    def pull_referrer(
        self,
        req: builtins.list[store_v1.PullReferrerRequest],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> builtins.list[store_v1.PullReferrerResponse]:
        return self._collect_stream(
            "pull_referrer",
            "Failed to pull referrer object",
            lambda: self._store_client.PullReferrer(iter(req), metadata=metadata),
        )

    def lookup(
        self,
        refs: builtins.list[core_v1.RecordRef],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> builtins.list[core_v1.RecordMeta]:
        return self._collect_stream(
            "lookup",
            "Failed to lookup object",
            lambda: self._store_client.Lookup(iter(refs), metadata=metadata),
        )

    def delete(
        self,
        refs: builtins.list[core_v1.RecordRef],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> None:
        self._invoke(
            "delete",
            "Failed to delete object",
            lambda: self._store_client.Delete(iter(refs), metadata=metadata),
        )

    def delete_referrer(
        self,
        req: store_v1.DeleteReferrerRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> store_v1.DeleteReferrerResponse:
        def call() -> store_v1.DeleteReferrerResponse:
            def request_iterator() -> Iterator[store_v1.DeleteReferrerRequest]:
                yield req

            responses = self._store_client.DeleteReferrer(
                request_iterator(),
                metadata=metadata,
            )
            for response in responses:
                return response
            msg = "DeleteReferrer returned no response"
            raise RuntimeError(msg)

        return self._invoke(
            "delete_referrer",
            "Failed to delete referrer",
            call,
        )
