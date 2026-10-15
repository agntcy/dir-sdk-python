# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
"""Tests for the libdirwrapper ctypes binding; no Directory server needed."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from agntcy.dir_sdk.client.config import Config
from agntcy.dir_sdk.client.native import NativeLibraryError, load_library
from agntcy.dir_sdk.client.native.library import find_library_path
from agntcy.dir_sdk.client.native.signing import native_client_config


def _library_available() -> bool:
    try:
        find_library_path()
    except NativeLibraryError:
        return False
    return True


class TestNativeConfig(unittest.TestCase):
    def test_config_translation_drops_empty_values(self) -> None:
        cfg = native_client_config(
            Config(server_address="dir:8888", auth_mode="jwt", jwt_audience="aud"),
            auth_token="tok",
        )
        assert cfg == {
            "server_address": "dir:8888",
            "auth_mode": "jwt",
            "jwt_audience": "aud",
            "oidc_scopes": ["openid", "profile", "email"],
            "auth_token": "tok",
        }

    def test_missing_override_raises(self) -> None:
        old = os.environ.get("DIR_WRAPPER_LIB")
        os.environ["DIR_WRAPPER_LIB"] = "/nonexistent/lib.dylib"
        try:
            with self.assertRaises(NativeLibraryError):
                find_library_path()
        finally:
            if old is None:
                del os.environ["DIR_WRAPPER_LIB"]
            else:
                os.environ["DIR_WRAPPER_LIB"] = old


@unittest.skipUnless(_library_available(), "libdirwrapper not built")
class TestNativeLibrary(unittest.TestCase):
    def test_unknown_handle_is_reported(self) -> None:
        with self.assertRaises(NativeLibraryError):
            load_library().call("CloseClient", 987654)

    def test_sign_and_verify_with_key_roundtrip(self) -> None:
        lib = load_library()
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "COSIGN_PASSWORD": "pw"}
            subprocess.run(
                ["cosign", "generate-key-pair"],
                cwd=tmp,
                env=env,
                check=True,
                capture_output=True,
            )
            private_key = (Path(tmp) / "cosign.key").read_text()

        cid = "baeareigr6xlwcsxuk2c7htbkcozdgctzrsqkj7e3gcquhdk4ij3dz6ndy"
        signed = lib.call(
            "SignWithKey",
            {"cid": cid, "private_key": private_key, "password": "pw"},
        )
        verified = lib.call(
            "VerifyWithKey",
            {
                "cid": cid,
                "public_keys": [signed["public_key"]],
                "signature": signed["signature"],
            },
        )
        assert verified["verified"] is True

        with self.assertRaises(NativeLibraryError):
            lib.call(
                "VerifyWithKey",
                {
                    "cid": cid + "x",
                    "public_keys": [signed["public_key"]],
                    "signature": signed["signature"],
                },
            )
