# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the runtime discovery client against an in-process server."""

from __future__ import annotations

import unittest
from collections.abc import Iterator
from concurrent import futures

import grpc
from agntcy.dir_sdk.client import RuntimeClient
from agntcy.dir_sdk.models import runtime_v1

WORKLOADS = [
    runtime_v1.Workload(
        id="a",
        runtime="docker",
        locators=[
            runtime_v1.WorkloadLocator(protocol="http", url="http://10.0.0.1:80")
        ],
    ),
    runtime_v1.Workload(id="b", runtime="kubernetes"),
]


class FakeDiscovery(runtime_v1.DiscoveryServiceServicer):
    """In-process dir-runtime; applies only the runtime_types filter."""

    def GetWorkload(  # noqa: N802
        self,
        request: runtime_v1.GetWorkloadRequest,
        context: grpc.ServicerContext,
    ) -> runtime_v1.Workload:
        for w in WORKLOADS:
            if w.id == request.id:
                return w
        context.abort(grpc.StatusCode.NOT_FOUND, request.id)
        raise AssertionError  # abort() raises; unreachable

    def ListWorkloads(  # noqa: N802
        self,
        request: runtime_v1.ListWorkloadsRequest,
        _context: grpc.ServicerContext,
    ) -> Iterator[runtime_v1.Workload]:
        for w in WORKLOADS:
            if not request.runtime_types or w.runtime in request.runtime_types:
                yield w


class TestRuntimeClient(unittest.TestCase):
    def setUp(self) -> None:
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
        runtime_v1.add_DiscoveryServiceServicer_to_server(FakeDiscovery(), self.server)
        port = self.server.add_insecure_port("127.0.0.1:0")
        self.server.start()
        self.client = RuntimeClient(f"127.0.0.1:{port}")

    def tearDown(self) -> None:
        self.client.close()
        self.server.stop(None)

    def test_list_workloads_with_filters(self) -> None:
        everything = self.client.list_workloads(runtime_v1.ListWorkloadsRequest())
        assert [w.id for w in everything] == ["a", "b"]

        docker = self.client.list_workloads(
            runtime_v1.ListWorkloadsRequest(runtime_types=["docker"])
        )
        assert len(docker) == 1
        assert docker[0].locators[0].url == "http://10.0.0.1:80"

    def test_get_workload(self) -> None:
        w = self.client.get_workload(runtime_v1.GetWorkloadRequest(id="b"))
        assert w.runtime == "kubernetes"

    def test_get_workload_not_found(self) -> None:
        with self.assertRaises(grpc.RpcError) as ctx:
            self.client.get_workload(runtime_v1.GetWorkloadRequest(id="missing"))
        assert ctx.exception.code() == grpc.StatusCode.NOT_FOUND
