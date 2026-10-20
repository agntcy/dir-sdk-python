# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the SPIFFE transport helpers that do not need a SPIRE agent."""

from __future__ import annotations

import sys
import unittest
import unittest.mock
from types import SimpleNamespace

from agntcy.dir_sdk.client.config import Config
from agntcy.dir_sdk.client.transport import channels
from agntcy.dir_sdk.client.transport.interceptors import JWTAuthInterceptor


class TestSpiffeTransport(unittest.TestCase):
    def test_jwt_interceptor_creates_workload_client_lazily(self) -> None:
        workload_client = unittest.mock.MagicMock()
        fake_spiffe = SimpleNamespace(WorkloadApiClient=workload_client)
        with unittest.mock.patch.dict(sys.modules, {"spiffe": fake_spiffe}):
            interceptor = JWTAuthInterceptor("unix:///spire.sock", "audience")
        workload_client.assert_called_once_with(socket_path="unix:///spire.sock")
        assert interceptor._workload_client is workload_client.return_value

    def test_channels_require_spiffe_socket_path(self) -> None:
        config = Config(spiffe_socket_path="")
        with self.assertRaises(ValueError):
            channels.create_x509_channel(config)
        with self.assertRaises(ValueError):
            channels.create_jwt_channel(config)

    def test_jwt_channel_requires_audience(self) -> None:
        config = Config(spiffe_socket_path="unix:///spire.sock", jwt_audience="")
        with self.assertRaises(ValueError):
            channels.create_jwt_channel(config)


if __name__ == "__main__":
    unittest.main()
