# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Interoperability tests between the SDK and the dirctl CLI.

Records signed by the SDK must verify with dirctl, and records signed by dirctl
must verify with the SDK. These tests need a running Directory server (see
DIRECTORY_CLIENT_SERVER_ADDRESS), the dirctl binary (DIRCTL_PATH or PATH) and
the cosign binary (COSIGN_PATH or PATH) and are skipped otherwise.
Only key-based signing is covered; keyless signing needs live Sigstore services.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
import uuid
from typing import Any

import grpc
from agntcy.dir_sdk.client import Client
from agntcy.dir_sdk.client.signing import referrer, verify
from agntcy.dir_sdk.models import core_v1, sign_v1, store_v1
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from nacl.secret import SecretBox

KEY_PASSWORD = "interop-pw"
DIRCTL = os.getenv("DIRCTL_PATH") or shutil.which("dirctl")
COSIGN = os.getenv("COSIGN_PATH") or shutil.which("cosign")


def _write_cosign_ed25519_key(directory: pathlib.Path) -> tuple[str, str]:
    """Write an Ed25519 key pair in the cosign encrypted format (cosign cannot)."""
    key = ed25519.Ed25519PrivateKey.generate()
    pkcs8 = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    salt, nonce = os.urandom(32), os.urandom(24)
    derived = hashlib.scrypt(
        KEY_PASSWORD.encode(),
        salt=salt,
        n=32768,
        r=8,
        p=1,
        maxmem=64 * 1024 * 1024,
        dklen=32,
    )
    ciphertext = SecretBox(derived).encrypt(pkcs8, nonce).ciphertext
    envelope = {
        "kdf": {
            "name": "scrypt",
            "params": {"N": 32768, "r": 8, "p": 1},
            "salt": base64.b64encode(salt).decode(),
        },
        "cipher": {"name": "nacl/secretbox", "nonce": base64.b64encode(nonce).decode()},
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    body = base64.b64encode(json.dumps(envelope).encode()).decode()
    lines = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    private_path = directory / "ed25519.key"
    private_path.write_text(
        "-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\n"
        f"{lines}\n-----END ENCRYPTED SIGSTORE PRIVATE KEY-----\n"
    )
    public_path = directory / "ed25519.pub"
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return str(private_path), str(public_path)


@unittest.skipUnless(DIRCTL and COSIGN, "dirctl and cosign binaries are required")
class TestDirctlInterop(unittest.TestCase):
    client: Client
    tmp: tempfile.TemporaryDirectory[str]
    keys: dict[str, tuple[str, str]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.client = Client()
        try:
            cls.client.push([cls._record("probe")])
        except grpc.RpcError as e:
            msg = f"Directory server is not reachable: {e}"
            raise unittest.SkipTest(msg) from e

        cls.tmp = tempfile.TemporaryDirectory()
        directory = pathlib.Path(cls.tmp.name)
        env = {**os.environ, "COSIGN_PASSWORD": KEY_PASSWORD}
        subprocess.run(
            [str(COSIGN), "generate-key-pair"],
            cwd=directory,
            env=env,
            check=True,
            capture_output=True,
        )
        cls.keys = {
            "ECDSA-P-256": (
                str(directory / "cosign.key"),
                str(directory / "cosign.pub"),
            ),
            "Ed25519": _write_cosign_ed25519_key(directory),
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    @staticmethod
    def _record(name: str) -> core_v1.Record:
        return core_v1.Record(
            data={
                "name": f"agntcy-interop-{name}-{uuid.uuid4().hex[:8]}",
                "version": "v3.0.0",
                "schema_version": "0.7.0",
                "description": "Record used to test dirctl and SDK interoperability.",
                "authors": ["Cisco Systems"],
                "created_at": "2025-03-19T17:06:37Z",
                "skills": [
                    {
                        "name": "natural_language_processing/natural_language_generation/text_completion",
                        "id": 10201,
                    }
                ],
                "locators": [
                    {
                        "type": "docker_image",
                        "url": "https://ghcr.io/agntcy/marketing-strategy",
                    }
                ],
                "domains": [{"name": "technology/networking", "id": 103}],
                "modules": [],
            }
        )

    def _push(self, name: str) -> core_v1.RecordRef:
        return self.client.push([self._record(name)])[0]

    @staticmethod
    def _dirctl(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "COSIGN_PASSWORD": KEY_PASSWORD,
            "DIRECTORY_CLIENT_SERVER_ADDRESS": os.getenv(
                "DIRECTORY_CLIENT_SERVER_ADDRESS", "0.0.0.0:8888"
            ),
        }
        return subprocess.run(
            [str(DIRCTL), *args],
            check=check,
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )

    def _dirctl_verify(self, cid: str, public_key: str | None = None) -> dict[str, Any]:
        args = ["verify", cid, "--output", "json"]
        if public_key:
            args += ["--key", public_key]
        result = self._dirctl(*args, check=False)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    def _sdk_sign(self, ref: core_v1.RecordRef, private_key: str) -> None:
        self.client.sign(
            sign_v1.SignRequest(
                record_ref=ref,
                provider=sign_v1.SignRequestProvider(
                    key=sign_v1.SignWithKey(
                        private_key=private_key, password=KEY_PASSWORD.encode()
                    )
                ),
            )
        )

    def _sdk_verify(
        self, ref: core_v1.RecordRef, public_key: str | None = None
    ) -> sign_v1.VerifyResponse:
        provider = (
            sign_v1.VerifyRequestProvider(
                key=sign_v1.VerifyWithKey(public_key=public_key)
            )
            if public_key
            else sign_v1.VerifyRequestProvider(any=sign_v1.VerifyWithAny())
        )
        return self.client.verify(
            sign_v1.VerifyRequest(record_ref=ref, provider=provider)
        )

    def _public_pem(self, algorithm: str) -> str:
        return pathlib.Path(self.keys[algorithm][1]).read_text()

    def test_sdk_signature_verifies_with_dirctl(self) -> None:
        for algorithm, (private_key, public_key) in self.keys.items():
            with self.subTest(algorithm):
                ref = self._push(f"sdk-{algorithm}")
                self._sdk_sign(ref, private_key)

                for result in (
                    self._dirctl_verify(ref.cid),
                    self._dirctl_verify(ref.cid, public_key),
                ):
                    assert result["success"], result
                    signer = result["signers"][0]["key"]
                    assert signer["algorithm"] == algorithm
                    assert signer["publicKey"] == self._public_pem(algorithm)

    def test_dirctl_signature_verifies_with_sdk(self) -> None:
        for algorithm, (private_key, public_key) in self.keys.items():
            with self.subTest(algorithm):
                ref = self._push(f"dirctl-{algorithm}")
                self._dirctl("sign", ref.cid, "--key", private_key)

                for response in (
                    self._sdk_verify(ref),
                    self._sdk_verify(ref, public_key),
                ):
                    assert response.success, response.error_message
                    signer = response.signers[0].key
                    assert signer.algorithm == algorithm
                    assert signer.public_key == self._public_pem(algorithm)

    def test_sdk_and_dirctl_produce_equivalent_referrers(self) -> None:
        for algorithm, (private_key, _) in self.keys.items():
            with self.subTest(algorithm):
                sdk_ref = self._push(f"equiv-sdk-{algorithm}")
                dirctl_ref = self._push(f"equiv-dirctl-{algorithm}")
                self._sdk_sign(sdk_ref, private_key)
                self._dirctl("sign", dirctl_ref.cid, "--key", private_key)

                sdk_sigs = self._pull_signatures(sdk_ref)
                dirctl_sigs = self._pull_signatures(dirctl_ref)
                assert len(sdk_sigs) == len(dirctl_sigs) == 1
                sdk_sig, dirctl_sig = sdk_sigs[0], dirctl_sigs[0]

                # Same populated fields and metadata; only the values that depend
                # on time and (for ECDSA) randomness may differ.
                populated = [
                    {field.name for field, _ in sig.ListFields()}
                    for sig in (sdk_sig, dirctl_sig)
                ]
                assert populated[0] == populated[1]
                assert sdk_sig.algorithm == dirctl_sig.algorithm == algorithm
                assert sdk_sig.content_bundle == dirctl_sig.content_bundle == ""
                assert self._pull_public_keys(sdk_ref) == self._pull_public_keys(
                    dirctl_ref
                )

    def test_signature_is_rejected_for_a_different_record(self) -> None:
        """A signature must only be valid for the CID it was created for."""
        private_key, public_key = self.keys["ECDSA-P-256"]
        signed = self._push("payload-signed")
        other = self._push("payload-other")
        self._sdk_sign(signed, private_key)

        # Re-attach the SDK's referrers to a different record.
        for sig in self._pull_signatures(signed):
            self._attach(other, sig)
        self._attach(other, sign_v1.PublicKey(key=self._public_pem("ECDSA-P-256")))
        assert not self._sdk_verify(other, public_key).success
        assert not self._dirctl_verify(other.cid, public_key).get("success", False)

    def test_wrong_key_is_rejected_by_both(self) -> None:
        private_key, _ = self.keys["ECDSA-P-256"]
        _, other_public = self.keys["Ed25519"]

        sdk_ref = self._push("wrong-key-sdk")
        self._sdk_sign(sdk_ref, private_key)
        dirctl_ref = self._push("wrong-key-dirctl")
        self._dirctl("sign", dirctl_ref.cid, "--key", private_key)

        for ref in (sdk_ref, dirctl_ref):
            assert not self._sdk_verify(ref, other_public).success
            assert not self._dirctl_verify(ref.cid, other_public).get("success", False)

    def test_cosign_verifies_sdk_signature(self) -> None:
        private_key, public_key = self.keys["ECDSA-P-256"]
        ref = self._push("cosign")
        self._sdk_sign(ref, private_key)
        signature = self._pull_signatures(ref)[0].signature

        payload = pathlib.Path(self.tmp.name) / "payload.txt"
        payload.write_bytes(ref.cid.encode())
        subprocess.run(
            [
                str(COSIGN),
                "verify-blob",
                "--key",
                public_key,
                "--signature",
                signature,
                "--insecure-ignore-tlog",
                str(payload),
            ],
            check=True,
            capture_output=True,
        )

    def _pull_signatures(self, ref: core_v1.RecordRef) -> list[sign_v1.Signature]:
        return verify.pull_signatures(self.client.store_service, ref)

    def _pull_public_keys(self, ref: core_v1.RecordRef) -> list[str]:
        return verify.pull_public_keys(self.client.store_service, ref)

    def _attach(
        self,
        ref: core_v1.RecordRef,
        message: sign_v1.Signature | sign_v1.PublicKey,
    ) -> None:
        record_referrer = (
            referrer.marshal_signature(message)
            if isinstance(message, sign_v1.Signature)
            else referrer.marshal_public_key(message)
        )
        self.client.push_referrer(
            [
                store_v1.PushReferrerRequest(
                    record_ref=ref,
                    type=record_referrer.type,
                    annotations=record_referrer.annotations,
                    created_at=record_referrer.created_at,
                    data=record_referrer.data,
                )
            ]
        )


if __name__ == "__main__":
    unittest.main()
