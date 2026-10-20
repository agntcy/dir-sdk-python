# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the SPIFFE transport helpers that do not need a SPIRE agent."""

from __future__ import annotations

import sys
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

from agntcy.dir_sdk.client.config import Config
from agntcy.dir_sdk.client.transport import channels
from agntcy.dir_sdk.client.transport.interceptors import JWTAuthInterceptor
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


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


def _self_signed_certificate() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "spire")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    return cert, key


class TestSpiffeChannels(unittest.TestCase):
    def _fake_spiffe(self, *, with_bundle: bool = True) -> tuple[SimpleNamespace, Any]:
        cert, key = _self_signed_certificate()
        source = unittest.mock.MagicMock()
        source.bundles = (
            [SimpleNamespace(x509_authorities=[cert])] if with_bundle else []
        )
        source.svid = SimpleNamespace(private_key=key, leaf=cert)
        fake = SimpleNamespace(
            WorkloadApiClient=unittest.mock.MagicMock(),
            X509Source=unittest.mock.MagicMock(return_value=source),
        )
        return fake, source

    def test_x509_channel(self) -> None:
        fake, _ = self._fake_spiffe()
        config = Config(spiffe_socket_path="unix:///spire.sock")
        with unittest.mock.patch.dict(sys.modules, {"spiffe": fake}):
            channel = channels.create_x509_channel(config)
        channel.close()
        fake.WorkloadApiClient.assert_called_once_with(socket_path="unix:///spire.sock")

    def test_jwt_channel(self) -> None:
        fake, source = self._fake_spiffe()
        config = Config(
            spiffe_socket_path="unix:///spire.sock", jwt_audience="directory"
        )
        with unittest.mock.patch.dict(sys.modules, {"spiffe": fake}):
            channel = channels.create_jwt_channel(config)
        channel.close()
        source.close.assert_called_once()

    def test_jwt_channel_requires_bundle(self) -> None:
        fake, source = self._fake_spiffe(with_bundle=False)
        config = Config(
            spiffe_socket_path="unix:///spire.sock", jwt_audience="directory"
        )
        with (
            unittest.mock.patch.dict(sys.modules, {"spiffe": fake}),
            self.assertRaises(RuntimeError),
        ):
            channels.create_jwt_channel(config)
        source.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
