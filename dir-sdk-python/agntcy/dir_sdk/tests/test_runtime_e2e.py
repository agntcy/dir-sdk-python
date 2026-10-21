# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""End-to-end tests of the runtime discovery client.

They run against a real ``dirctl daemon`` that discovers a labelled Docker
container, and skip unless ``DIRECTORY_RUNTIME_ADDRESS`` is set. Run them with
``task test:runtime``, which starts the daemon and the container.
"""

from __future__ import annotations

import os
import time
import unittest

import grpc
from agntcy.dir_sdk.client import RuntimeClient
from agntcy.dir_sdk.models import runtime_v1

ADDRESS = os.environ.get("DIRECTORY_RUNTIME_ADDRESS", "")
NAME = os.environ.get("RUNTIME_E2E_WORKLOAD_NAME", "")
LABELS = {"sdk.agntcy/discover": "true"}


@unittest.skipUnless(ADDRESS, "DIRECTORY_RUNTIME_ADDRESS not set")
class TestRuntimeE2E(unittest.TestCase):
    def setUp(self) -> None:
        self.client = RuntimeClient(ADDRESS)

    def tearDown(self) -> None:
        self.client.close()

    def _list(
        self,
        labels: dict[str, str] | None = None,
        runtime_types: list[str] | None = None,
        locator_protocols: list[str] | None = None,
    ) -> list[runtime_v1.Workload]:
        return self.client.list_workloads(
            runtime_v1.ListWorkloadsRequest(
                labels=LABELS if labels is None else labels,
                runtime_types=runtime_types,
                locator_protocols=locator_protocols,
            )
        )

    def _discovered(self) -> runtime_v1.Workload:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            for w in self._list():
                if w.name == NAME:
                    return w
            time.sleep(2)
        self.fail(f"workload {NAME} was never discovered")

    def _matches(
        self,
        labels: dict[str, str] | None = None,
        runtime_types: list[str] | None = None,
        locator_protocols: list[str] | None = None,
    ) -> bool:
        listed = self._list(labels, runtime_types, locator_protocols)
        return any(w.name == NAME for w in listed)

    def test_lists_and_gets_the_discovered_workload(self) -> None:
        listed = self._discovered()
        assert listed.runtime == "docker"
        assert listed.type == "container"
        assert listed.labels["sdk.agntcy/agent-type"] == "a2a"
        assert any(
            loc.protocol == "tcp" and loc.url.startswith("tcp://")
            for loc in listed.locators
        )

        got = self.client.get_workload(runtime_v1.GetWorkloadRequest(id=listed.id))
        assert got.id == listed.id
        assert got.name == NAME

    def test_filters_narrow_the_result(self) -> None:
        self._discovered()
        assert self._matches(runtime_types=["docker"])
        assert self._matches(locator_protocols=["tcp"])
        assert not self._matches(runtime_types=["kubernetes"])
        assert not self._matches(locator_protocols=["slim"])
        assert not self._matches(labels={"sdk.agntcy/discover": "false"})

    def test_unknown_workload_fails(self) -> None:
        with self.assertRaises(grpc.RpcError) as ctx:
            self.client.get_workload(runtime_v1.GetWorkloadRequest(id="does-not-exist"))
        assert "workload not found" in str(ctx.exception.details())
