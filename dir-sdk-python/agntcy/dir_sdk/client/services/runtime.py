# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Runtime discovery service wrappers."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from agntcy.dir_sdk.client.services.base import RpcServiceBase
from agntcy.dir_sdk.models import runtime_v1


class RuntimeService(RpcServiceBase):
    def __init__(
        self,
        discovery_client: runtime_v1.DiscoveryServiceStub,
        logger: logging.Logger,
    ) -> None:
        super().__init__(logger)
        self._discovery_client = discovery_client

    def get_workload(
        self,
        req: runtime_v1.GetWorkloadRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> runtime_v1.Workload:
        return self._invoke(
            "get_workload",
            "Failed to get workload",
            lambda: self._discovery_client.GetWorkload(req, metadata=metadata),
        )

    def list_workloads(
        self,
        req: runtime_v1.ListWorkloadsRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> list[runtime_v1.Workload]:
        return self._collect_stream(
            "list_workloads",
            "Failed to list workloads",
            lambda: self._discovery_client.ListWorkloads(req, metadata=metadata),
        )
