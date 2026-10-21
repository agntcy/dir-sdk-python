# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Client for the runtime discovery API served by dir-runtime."""

from __future__ import annotations

import logging
from collections.abc import Sequence

import grpc
from agntcy.dir_sdk.client.services.runtime import RuntimeService
from agntcy.dir_sdk.models import runtime_v1

logger = logging.getLogger("agntcy.dir_sdk.runtime")


class RuntimeClient:
    """Client for ``agntcy.dir.runtime.v1.DiscoveryService``.

    dir-runtime (and ``dirctl daemon``) runs at its own address, so this is
    separate from :class:`~agntcy.dir_sdk.client.Client`: the Directory's
    credentials, such as the OIDC token, are never sent to it.
    """

    DEFAULT_SERVER_ADDRESS = "localhost:8888"

    def __init__(
        self,
        server_address: str = DEFAULT_SERVER_ADDRESS,
        channel: grpc.Channel | None = None,
    ) -> None:
        self.server_address = server_address
        self.channel = channel or grpc.insecure_channel(server_address)

        # Expose the raw stub for advanced callers.
        self.discovery_client = runtime_v1.DiscoveryServiceStub(self.channel)
        self.runtime_service = RuntimeService(self.discovery_client, logger)

    def close(self) -> None:
        self.channel.close()

    def get_workload(
        self,
        req: runtime_v1.GetWorkloadRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> runtime_v1.Workload:
        return self.runtime_service.get_workload(req, metadata)

    def list_workloads(
        self,
        req: runtime_v1.ListWorkloadsRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> list[runtime_v1.Workload]:
        return self.runtime_service.list_workloads(req, metadata)
