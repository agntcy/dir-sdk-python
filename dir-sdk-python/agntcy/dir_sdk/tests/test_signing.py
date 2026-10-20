# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Offline unit tests for native signing and verification."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import tempfile
import unittest
import unittest.mock
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

from agntcy.dir_sdk.client.services.store import StoreService
from agntcy.dir_sdk.client.signing import ed25519ph, keys, oidc, referrer
from agntcy.dir_sdk.client.signing import verify as verify_mod
from agntcy.dir_sdk.client.signing.sign import sign_blob_with_key, sign_record
from agntcy.dir_sdk.client.signing.verify import verify_record
from agntcy.dir_sdk.models import core_v1, sign_v1, store_v1
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from nacl.secret import SecretBox

CID = "bafkreibtestcidforsigning"

# Key pair generated with `cosign generate-key-pair` (password: "pw").
COSIGN_KEY = """-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----
eyJrZGYiOnsibmFtZSI6InNjcnlwdCIsInBhcmFtcyI6eyJOIjo2NTUzNiwiciI6
OCwicCI6MX0sInNhbHQiOiJNRWc4VThsVWZiTnZCbXd2UWZiMjVOcFZWY01VME9Z
Rm43c0o5L1FtN0RZPSJ9LCJjaXBoZXIiOnsibmFtZSI6Im5hY2wvc2VjcmV0Ym94
Iiwibm9uY2UiOiJsRjQvNWNpc0w3TWRJREVLbm52Wm91UEgrTit5cG1waiJ9LCJj
aXBoZXJ0ZXh0Ijoid2hKc09qZGFmdHJ6eGRBUk1PbCtJY3JGbC9Gc056Z3dQaGJU
OXpwZStLSnJZNUk0SHNTNHUrMjhDVDZYeXF6VDFDQWlvM3RkeGQ2K1JUN1pwRTVV
K2h6Z2ZmZnA4M2tOZnpscENpZ1NYSEVhK2poQlE5dUxZSk40d1IrRFRiaHFoc2dj
T2VFdkoxaG5HLy9CNm9EeDJkMmVITkw4c0ltSnk5OTY3aDZRQ2pJRkdnK0xOTmM3
QlBuRG5YU0N0aWwyaFNkZis1a2NSVmNHZFE9PSJ9
-----END ENCRYPTED SIGSTORE PRIVATE KEY-----
"""
COSIGN_PUB = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEut6/BVok2fw1ILDkX10HQxmriTAS
I5pw7NLDC6Bi3FKQl1FkOmVubQSbaj07C8LP1E2yDqOM1buTnz33HGiCEg==
-----END PUBLIC KEY-----
"""
# `cosign sign-blob --key` over the payload b"bafytestcid".
COSIGN_BLOB_SIGNATURE = (
    "MEUCIA8RuVpvLWX1s5Nr2JoPZOBwc+WYxUb1YqPttPKcA4OdAiEA8uOpbZkvcqc/"
    "sZUsqGWNAESLuDVzJN6jmJj06EDA1ts="
)


def _pem_private(key: object, password: bytes | None = None) -> str:
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    ).decode()


def _cosign_encrypt(key: object, password: bytes) -> str:
    """Encode a key in the cosign encrypted-key format (small scrypt cost)."""
    pkcs8 = key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    salt, nonce = os.urandom(32), os.urandom(24)
    derived = hashlib.scrypt(password, salt=salt, n=1024, r=8, p=1, dklen=32)
    ciphertext = SecretBox(derived).encrypt(pkcs8, nonce).ciphertext
    envelope = {
        "kdf": {
            "name": "scrypt",
            "params": {"N": 1024, "r": 8, "p": 1},
            "salt": base64.b64encode(salt).decode(),
        },
        "cipher": {"name": "nacl/secretbox", "nonce": base64.b64encode(nonce).decode()},
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    body = base64.b64encode(json.dumps(envelope).encode()).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "\n".join(
        [
            "-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----",
            *lines,
            "-----END ENCRYPTED SIGSTORE PRIVATE KEY-----",
            "",
        ]
    )


def _make_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test-fulcio")]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert


def _issue_leaf(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    public_key: ec.EllipticCurvePublicKey,
    subject: str,
) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    issuer = b"https://issuer.example"
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(2)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]), False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(subject)]),
            True,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                oidc._OID_ISSUER_V2, b"\x0c" + bytes([len(issuer)]) + issuer
            ),
            False,
        )
        .sign(ca_key, hashes.SHA256())
    )


class FakeStore(StoreService):
    """In-memory stand-in for the store referrer and lookup RPCs."""

    def __init__(self, known_cids: Sequence[str] = (CID,)) -> None:
        self.known_cids = set(known_cids)
        self.pushed: list[store_v1.PushReferrerRequest] = []

    def push_referrer(
        self,
        req: list[store_v1.PushReferrerRequest],
        metadata: Sequence[tuple[str, str]] | None = None,  # noqa: ARG002
    ) -> list[store_v1.PushReferrerResponse]:
        self.pushed.extend(req)
        return [store_v1.PushReferrerResponse(success=True) for _ in req]

    def pull_referrer(
        self,
        req: list[store_v1.PullReferrerRequest],
        metadata: Sequence[tuple[str, str]] | None = None,  # noqa: ARG002
    ) -> list[store_v1.PullReferrerResponse]:
        out = []
        for r in req:
            for pushed in self.pushed:
                if (
                    pushed.record_ref.cid == r.record_ref.cid
                    and pushed.type == r.referrer_type
                ):
                    out.append(
                        store_v1.PullReferrerResponse(
                            referrer=core_v1.RecordReferrer(
                                type=pushed.type, data=pushed.data
                            )
                        )
                    )
        return out

    def lookup(
        self,
        refs: list[core_v1.RecordRef],
        metadata: Sequence[tuple[str, str]] | None = None,  # noqa: ARG002
    ) -> list[core_v1.RecordMeta]:
        for ref in refs:
            if ref.cid not in self.known_cids:
                msg = "record not found"
                raise RuntimeError(msg)
        return [core_v1.RecordMeta(cid=ref.cid) for ref in refs]


def _key_sign_request(private_key: str, password: bytes = b"") -> sign_v1.SignRequest:
    return sign_v1.SignRequest(
        record_ref=core_v1.RecordRef(cid=CID),
        provider=sign_v1.SignRequestProvider(
            key=sign_v1.SignWithKey(private_key=private_key, password=password)
        ),
    )


class TestEd25519ph(unittest.TestCase):
    def test_rfc8032_vector(self) -> None:
        seed = bytes.fromhex(
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
        )
        pub = bytes.fromhex(
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
        )
        expected = bytes.fromhex(
            "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41"
            "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406"
        )
        assert ed25519ph.public_key(seed) == pub
        assert ed25519ph.sign(seed, b"abc") == expected
        assert ed25519ph.verify(pub, b"abc", expected)
        assert not ed25519ph.verify(pub, b"abd", expected)


class TestKeys(unittest.TestCase):
    def test_roundtrip_plain_and_encrypted(self) -> None:
        cases = {
            "ECDSA-P-256": ec.generate_private_key(ec.SECP256R1()),
            "ECDSA-P-384": ec.generate_private_key(ec.SECP384R1()),
            "RSA-2048": rsa.generate_private_key(65537, 2048),
            "Ed25519": ed25519.Ed25519PrivateKey.generate(),
        }
        for algorithm, key in cases.items():
            for pem, password in (
                (_pem_private(key), b""),
                (_pem_private(key, b"secret"), b"secret"),
                (_cosign_encrypt(key, b"secret"), b"secret"),
            ):
                with self.subTest(algorithm=algorithm, encrypted=bool(password)):
                    signature, public_key = sign_blob_with_key(
                        CID.encode(),
                        sign_v1.SignWithKey(private_key=pem, password=password),
                    )
                    assert signature.algorithm == algorithm
                    assert signature.signed_at.endswith("Z")
                    loaded = keys.load_public_key(public_key.key)
                    raw = base64.b64decode(signature.signature)
                    assert keys.verify_message(loaded, raw, CID.encode())
                    assert not keys.verify_message(loaded, raw, b"other")

    def test_ed25519_signs_as_ph(self) -> None:
        key = ed25519.Ed25519PrivateKey.generate()
        signature, _ = sign_blob_with_key(
            CID.encode(), sign_v1.SignWithKey(private_key=_pem_private(key))
        )
        raw = base64.b64decode(signature.signature)
        # A pure Ed25519 verifier must reject it; only the ph fallback accepts.
        pub = key.public_key()
        with self.assertRaises(Exception):  # noqa: B017
            pub.verify(raw, CID.encode())
        assert keys.verify_message(pub, raw, CID.encode())

    def test_key_file_reference(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "cosign.key"
            path.write_text(_cosign_encrypt(key, b"pw"))
            signature, public_key = sign_blob_with_key(
                CID.encode(), sign_v1.SignWithKey(private_key=str(path), password=b"pw")
            )
            pub_path = pathlib.Path(tmp) / "cosign.pub"
            pub_path.write_text(public_key.key)
            loaded = keys.load_public_key(str(pub_path))
            assert keys.verify_message(
                loaded, base64.b64decode(signature.signature), CID.encode()
            )

    def test_wrong_password_and_missing_key(self) -> None:
        pem = _cosign_encrypt(ec.generate_private_key(ec.SECP256R1()), b"right")
        with self.assertRaises(ValueError):
            sign_blob_with_key(
                CID.encode(), sign_v1.SignWithKey(private_key=pem, password=b"wrong")
            )
        with self.assertRaises(ValueError):
            sign_blob_with_key(CID.encode(), sign_v1.SignWithKey(private_key="/nope"))
        with self.assertRaises(ValueError):
            sign_blob_with_key(CID.encode(), sign_v1.SignWithKey())

    def test_real_cosign_key_and_signature(self) -> None:
        signature, public_key = sign_blob_with_key(
            b"bafytestcid",
            sign_v1.SignWithKey(private_key=COSIGN_KEY, password=b"pw"),
        )
        assert public_key.key == COSIGN_PUB
        assert signature.algorithm == "ECDSA-P-256"
        pub = keys.load_public_key(COSIGN_PUB)
        # Signature produced by the cosign CLI verifies with our verifier.
        assert keys.verify_message(
            pub, base64.b64decode(COSIGN_BLOB_SIGNATURE), b"bafytestcid"
        )
        # And ours verifies with the same verifier path.
        assert keys.verify_message(
            pub, base64.b64decode(signature.signature), b"bafytestcid"
        )


class TestReferrerEncoding(unittest.TestCase):
    def test_signature_referrer(self) -> None:
        signature = sign_v1.Signature(
            signature="c2ln",
            algorithm="ECDSA-P-256",
            signed_at="2026-01-02T03:04:05Z",
            content_type="application/vnd.dev.sigstore.bundle.v0.3+json",
            content_bundle='{"a":1}',
            certificate="Y2VydA==",
        )
        ref = referrer.marshal_signature(signature)
        assert ref.type == "agntcy.dir.sign.v1.Signature"
        assert dict(ref.data.fields.items()).keys() == {
            "signature",
            "algorithm",
            "signedAt",
            "contentType",
            "contentBundle",
            "certificate",
        }
        assert ref.data["signedAt"] == "2026-01-02T03:04:05Z"
        assert referrer.unmarshal_signature(ref) == signature

    def test_signature_referrer_omits_empty_fields(self) -> None:
        ref = referrer.marshal_signature(sign_v1.Signature(signature="c2ln"))
        assert list(ref.data.fields.keys()) == ["signature"]

    def test_public_key_referrer(self) -> None:
        public_key = sign_v1.PublicKey(key=COSIGN_PUB)
        ref = referrer.marshal_public_key(public_key)
        assert ref.type == "agntcy.dir.sign.v1.PublicKey"
        assert list(ref.data.fields.keys()) == ["key"]
        assert referrer.unmarshal_public_key(ref) == public_key

    def test_unmarshal_requires_data(self) -> None:
        with self.assertRaises(ValueError):
            referrer.unmarshal_signature(core_v1.RecordReferrer())


class TestSignAndVerify(unittest.TestCase):
    def _signed_store(self) -> FakeStore:
        store = FakeStore()
        sign_record(store, _key_sign_request(COSIGN_KEY, b"pw"))
        return store

    def test_sign_pushes_public_key_then_signature(self) -> None:
        store = self._signed_store()
        assert [p.type for p in store.pushed] == [
            "agntcy.dir.sign.v1.PublicKey",
            "agntcy.dir.sign.v1.Signature",
        ]
        assert all(p.record_ref.cid == CID for p in store.pushed)
        signature = referrer.unmarshal_signature(
            core_v1.RecordReferrer(data=store.pushed[1].data)
        )
        assert not signature.content_bundle
        assert signature.algorithm == "ECDSA-P-256"

    def test_verify_default_any_key_and_dedupe(self) -> None:
        store = self._signed_store()
        sign_record(store, _key_sign_request(COSIGN_KEY, b"pw"))  # same signer again
        response = verify_record(
            store, sign_v1.VerifyRequest(record_ref=core_v1.RecordRef(cid=CID))
        )
        assert response.success
        assert len(response.signers) == 1
        assert response.signers[0].key.public_key == COSIGN_PUB
        assert response.signers[0].key.algorithm == "ECDSA-P-256"

    def test_verify_with_key_provider(self) -> None:
        store = self._signed_store()
        ok = verify_record(
            store,
            sign_v1.VerifyRequest(
                record_ref=core_v1.RecordRef(cid=CID),
                provider=sign_v1.VerifyRequestProvider(
                    key=sign_v1.VerifyWithKey(public_key=COSIGN_PUB)
                ),
            ),
        )
        assert ok.success
        other = ec.generate_private_key(ec.SECP256R1()).public_key()
        other_pem = other.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        bad = verify_record(
            store,
            sign_v1.VerifyRequest(
                record_ref=core_v1.RecordRef(cid=CID),
                provider=sign_v1.VerifyRequestProvider(
                    key=sign_v1.VerifyWithKey(public_key=other_pem)
                ),
            ),
        )
        assert not bad.success
        assert (
            bad.error_message
            == "no valid signatures found matching verification criteria"
        )

    def test_verify_public_key_file_reference(self) -> None:
        store = self._signed_store()
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "cosign.pub"
            path.write_text(COSIGN_PUB)
            response = verify_record(
                store,
                sign_v1.VerifyRequest(
                    record_ref=core_v1.RecordRef(cid=CID),
                    provider=sign_v1.VerifyRequestProvider(
                        key=sign_v1.VerifyWithKey(public_key=str(path))
                    ),
                ),
            )
        assert response.success

    def test_verify_no_signatures_and_record_not_found(self) -> None:
        empty = FakeStore()
        response = verify_record(
            empty, sign_v1.VerifyRequest(record_ref=core_v1.RecordRef(cid=CID))
        )
        assert not response.success
        assert response.error_message == "no signatures found"

        missing = verify_record(
            empty, sign_v1.VerifyRequest(record_ref=core_v1.RecordRef(cid="unknown"))
        )
        assert not missing.success
        assert missing.error_message == "record not found"

    def test_verify_requires_cid(self) -> None:
        with self.assertRaises(ValueError):
            verify_record(FakeStore(), sign_v1.VerifyRequest())

    def test_signature_for_other_record_is_rejected(self) -> None:
        store = FakeStore(known_cids=(CID, "other"))
        sign_record(store, _key_sign_request(COSIGN_KEY, b"pw"))
        # Re-attach CID's signature referrers to another record.
        for pushed in list(store.pushed):
            moved = store_v1.PushReferrerRequest()
            moved.CopyFrom(pushed)
            moved.record_ref.cid = "other"
            store.pushed.append(moved)
        response = verify_record(
            store, sign_v1.VerifyRequest(record_ref=core_v1.RecordRef(cid="other"))
        )
        assert not response.success

    def test_sign_validation(self) -> None:
        store = FakeStore()
        with self.assertRaises(ValueError):
            sign_record(
                store, sign_v1.SignRequest(record_ref=core_v1.RecordRef(cid=CID))
            )
        with self.assertRaises(ValueError):
            sign_record(
                store,
                sign_v1.SignRequest(
                    provider=sign_v1.SignRequestProvider(
                        key=sign_v1.SignWithKey(private_key=COSIGN_KEY)
                    )
                ),
            )
        with self.assertRaises(RuntimeError):
            sign_record(store, _key_sign_request("/nope"))


class TestOIDC(unittest.TestCase):
    def test_value_matcher(self) -> None:
        assert oidc.get_value_matcher("") == ("", ".*")
        assert oidc.get_value_matcher("https://github.com/") == (
            "",
            "https://github.com/",
        )
        assert oidc.get_value_matcher("(unclosed") == ("(unclosed", "")

    def test_summarize_certificate(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name(
            [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "sigstore-intermediate")]
        )
        issuer = b"https://issuer.example"
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(minutes=10))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier("https://example.com/wf")]
                ),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(
                    oidc._OID_ISSUER_V2,
                    b"\x0c" + bytes([len(issuer)]) + issuer,
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        summary = oidc._summarize_certificate(cert)
        assert summary.issuer == "https://issuer.example"
        assert summary.subject == "https://example.com/wf"
        assert summary.certificate_issuer == "CN=sigstore-intermediate"

    def _synthetic_signature(
        self, tmp: str, subject: str = "https://example.com/wf@refs/heads/main"
    ) -> tuple[sign_v1.Signature, str]:
        """Create a bundle signed by a throwaway CA and the matching trusted root."""
        ca_key, ca_cert = _make_ca()
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf = _issue_leaf(ca_key, ca_cert, leaf_key.public_key(), subject)

        raw_signature = leaf_key.sign(CID.encode(), ec.ECDSA(hashes.SHA256()))
        digest = hashlib.sha256(CID.encode()).digest()
        bundle = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "certificate": {
                    "rawBytes": base64.b64encode(
                        leaf.public_bytes(serialization.Encoding.DER)
                    ).decode()
                },
                "tlogEntries": [],
            },
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": base64.b64encode(digest).decode(),
                },
                "signature": base64.b64encode(raw_signature).decode(),
            },
        }
        trusted_root = {
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": [],
            "certificateAuthorities": [
                {
                    "subject": {"organization": "test", "commonName": "test-fulcio"},
                    "uri": "https://fulcio.test",
                    "certChain": {
                        "certificates": [
                            {
                                "rawBytes": base64.b64encode(
                                    ca_cert.public_bytes(serialization.Encoding.DER)
                                ).decode()
                            }
                        ]
                    },
                    "validFor": {"start": "2020-01-01T00:00:00Z"},
                }
            ],
            "ctlogs": [],
            "timestampAuthorities": [],
        }
        root_path = pathlib.Path(tmp) / "trusted_root.json"
        root_path.write_text(json.dumps(trusted_root))
        signature = sign_v1.Signature(
            signature=base64.b64encode(raw_signature).decode(),
            content_bundle=json.dumps(bundle),
            content_type="application/vnd.dev.sigstore.bundle.v0.3+json",
        )
        return signature, str(root_path)

    def _verify_synthetic(
        self,
        signature: sign_v1.Signature,
        root_path: str,
        *,
        issuer: str = "",
        subject: str = "",
        payload: bytes = CID.encode(),
        ignore_tlog: bool = False,
        ignore_tsa: bool = False,
        ignore_sct: bool = False,
    ) -> sign_v1.SignerInfo:
        return oidc.verify_with_oidc(
            payload,
            sign_v1.VerifyWithOIDC(
                issuer=issuer,
                subject=subject,
                options=sign_v1.VerifyOptionsOIDC(
                    trusted_root_path=root_path,
                    ignore_tlog=ignore_tlog,
                    ignore_tsa=ignore_tsa,
                    ignore_sct=ignore_sct,
                ),
            ),
            signature,
        )

    def test_verify_bundle_with_local_trusted_root(self) -> None:
        relaxed: dict[str, Any] = {
            "ignore_tlog": True,
            "ignore_tsa": True,
            "ignore_sct": True,
        }
        with tempfile.TemporaryDirectory() as tmp:
            signature, root_path = self._synthetic_signature(tmp)

            info = self._verify_synthetic(signature, root_path, **relaxed)
            assert info.oidc.issuer == "https://issuer.example"
            assert info.oidc.subject == "https://example.com/wf@refs/heads/main"
            assert info.oidc.certificate_issuer == "CN=test-fulcio"

            # Exact and regular expression identity matchers.
            self._verify_synthetic(
                signature,
                root_path,
                issuer="https://issuer.example",
                subject="https://example.com/wf@refs/heads/main",
                **relaxed,
            )
            self._verify_synthetic(
                signature, root_path, subject=r"^https://example\.com/.*", **relaxed
            )

            # Mismatching identity, payload or trust anchor are rejected.
            with self.assertRaises(oidc.OIDCError):
                self._verify_synthetic(
                    signature, root_path, issuer="https://other.example", **relaxed
                )
            with self.assertRaises(oidc.OIDCError):
                self._verify_synthetic(
                    signature, root_path, subject="https://evil.example/.*", **relaxed
                )
            with self.assertRaises(oidc.OIDCError):
                self._verify_synthetic(
                    signature, root_path, payload=b"other-cid", **relaxed
                )
            _, other_root = self._synthetic_signature(tmp)
            with self.assertRaises(oidc.OIDCError):
                self._verify_synthetic(signature, other_root, **relaxed)

            # Without ignoring them, missing timestamps/log/SCT are rejected.
            stricter: tuple[dict[str, Any], ...] = (
                {"ignore_tlog": True, "ignore_sct": True},  # TSA required
                {"ignore_tsa": True, "ignore_sct": True},  # tlog required
                {"ignore_tlog": True, "ignore_tsa": True},  # SCT required
            )
            for strict in stricter:
                with self.assertRaises(oidc.OIDCError):
                    self._verify_synthetic(signature, root_path, **strict)

    def test_verify_with_any_and_oidc_provider_through_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            signature, root_path = self._synthetic_signature(tmp)
            relaxed = sign_v1.VerifyOptionsOIDC(
                trusted_root_path=root_path,
                ignore_tlog=True,
                ignore_tsa=True,
                ignore_sct=True,
            )
            store = FakeStore()
            store.pushed.append(
                store_v1.PushReferrerRequest(
                    record_ref=core_v1.RecordRef(cid=CID),
                    type=referrer.SIGNATURE_REFERRER_TYPE,
                    data=referrer.marshal_signature(signature).data,
                )
            )
            for provider in (
                sign_v1.VerifyRequestProvider(
                    any=sign_v1.VerifyWithAny(oidc_options=relaxed)
                ),
                sign_v1.VerifyRequestProvider(
                    oidc=sign_v1.VerifyWithOIDC(
                        issuer="https://issuer.example", options=relaxed
                    )
                ),
            ):
                response = verify_record(
                    store,
                    sign_v1.VerifyRequest(
                        record_ref=core_v1.RecordRef(cid=CID), provider=provider
                    ),
                )
                assert response.success, response.error_message
                assert response.signers[0].oidc.issuer == "https://issuer.example"

            # An identity mismatch is reported as a failed verification.
            denied = verify_record(
                store,
                sign_v1.VerifyRequest(
                    record_ref=core_v1.RecordRef(cid=CID),
                    provider=sign_v1.VerifyRequestProvider(
                        oidc=sign_v1.VerifyWithOIDC(
                            issuer="https://other.example", options=relaxed
                        )
                    ),
                ),
            )
            assert not denied.success

    def test_sign_with_oidc_produces_verifiable_bundle(self) -> None:
        ca_key, ca_cert = _make_ca()

        class FakeFulcio:
            def __init__(self, url: str) -> None:
                self.url = url
                self.signing_cert = self

            def post(
                self, csr: x509.CertificateSigningRequest, _identity: object
            ) -> SimpleNamespace:
                public_key = csr.public_key()
                assert isinstance(public_key, ec.EllipticCurvePublicKey)
                return SimpleNamespace(
                    cert=_issue_leaf(
                        ca_key, ca_cert, public_key, "https://example.com/id"
                    )
                )

        class FakeTSA:
            def __init__(self, url: str) -> None:
                self.url = url

            def request_timestamp(self, _signature: bytes) -> SimpleNamespace:
                return SimpleNamespace(as_bytes=lambda: b"fake-timestamp")

        with (
            tempfile.TemporaryDirectory() as tmp,
            unittest.mock.patch.object(oidc, "FulcioClient", FakeFulcio),
            unittest.mock.patch.object(oidc, "TimestampAuthorityClient", FakeTSA),
            unittest.mock.patch.object(oidc, "IdentityToken", lambda token, **_: token),
        ):
            signature, public_key = oidc.sign_blob_with_oidc(
                CID.encode(),
                sign_v1.SignWithOIDC(
                    id_token="token",
                    options=sign_v1.SignOptionsOIDC(skip_tlog=True),
                ),
            )
            assert signature.content_type.startswith(
                "application/vnd.dev.sigstore.bundle"
            )
            assert signature.signed_at.endswith("Z")
            assert signature.certificate
            assert public_key.key.startswith("-----BEGIN PUBLIC KEY-----")
            bundle = json.loads(signature.content_bundle)
            assert bundle["verificationMaterial"]["certificate"]["rawBytes"] == (
                signature.certificate
            )
            assert bundle["messageSignature"]["signature"] == signature.signature

            root_path = pathlib.Path(tmp) / "trusted_root.json"
            root_path.write_text(
                json.dumps(
                    {
                        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
                        "tlogs": [],
                        "certificateAuthorities": [
                            {
                                "subject": {"organization": "t", "commonName": "t"},
                                "uri": "https://fulcio.test",
                                "certChain": {
                                    "certificates": [
                                        {
                                            "rawBytes": base64.b64encode(
                                                ca_cert.public_bytes(
                                                    serialization.Encoding.DER
                                                )
                                            ).decode()
                                        }
                                    ]
                                },
                                "validFor": {"start": "2020-01-01T00:00:00Z"},
                            }
                        ],
                        "ctlogs": [],
                        "timestampAuthorities": [],
                    }
                )
            )
            info = self._verify_synthetic(
                signature,
                str(root_path),
                subject="https://example.com/id",
                ignore_tlog=True,
                ignore_tsa=True,
                ignore_sct=True,
            )
            assert info.oidc.subject == "https://example.com/id"

    def test_invalid_bundle(self) -> None:
        with self.assertRaises(oidc.OIDCError):
            oidc.verify_with_oidc(
                CID.encode(),
                sign_v1.VerifyWithOIDC(),
                sign_v1.Signature(content_bundle="not json"),
            )

    def test_sign_requires_reachable_services(self) -> None:
        with self.assertRaises(oidc.OIDCError):
            oidc.sign_blob_with_oidc(
                CID.encode(), sign_v1.SignWithOIDC(id_token="not-a-jwt")
            )


class TestKeysEdgeCases(unittest.TestCase):
    @staticmethod
    def _encrypted_pem(envelope: object | None = None, body: str | None = None) -> str:
        if body is None:
            body = base64.b64encode(json.dumps(envelope).encode()).decode()
        return (
            "-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\n"
            f"{body}\n"
            "-----END ENCRYPTED SIGSTORE PRIVATE KEY-----\n"
        )

    def test_malformed_encrypted_keys(self) -> None:
        good = {
            "kdf": {
                "name": "scrypt",
                "params": {"N": 1024, "r": 8, "p": 1},
                "salt": base64.b64encode(b"salt").decode(),
            },
            "cipher": {
                "name": "nacl/secretbox",
                "nonce": base64.b64encode(os.urandom(24)).decode(),
            },
            "ciphertext": base64.b64encode(b"garbage").decode(),
        }
        bad_kdf = {**good, "kdf": {**good["kdf"], "name": "argon2"}}  # type: ignore[dict-item]
        bad_cipher = {**good, "cipher": {"name": "aes", "nonce": ""}}
        missing = {k: v for k, v in good.items() if k != "ciphertext"}
        cases = {
            "unsupported KDF": self._encrypted_pem(bad_kdf),
            "unsupported cipher": self._encrypted_pem(bad_cipher),
            "invalid encrypted key format": self._encrypted_pem(missing),
            "decrypt": self._encrypted_pem(good),
            "invalid PEM body": self._encrypted_pem(body="abc"),
        }
        for expected, pem in cases.items():
            with self.subTest(expected), self.assertRaises(keys.KeyLoadError) as ctx:
                keys.load_private_key(pem, b"pw")
            assert expected in str(ctx.exception)

    def test_unsupported_key_types(self) -> None:
        x25519_private = x25519.X25519PrivateKey.generate()
        with self.assertRaises(keys.KeyLoadError):
            keys.load_private_key(_pem_private(x25519_private))
        x25519_public = x25519_private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with self.assertRaises(keys.KeyLoadError):
            keys.load_public_key(x25519_public.decode())
        assert keys.detect_key_algorithm(x25519_public.decode()) == "unknown"

    def test_key_reference_errors(self) -> None:
        with self.assertRaises(keys.KeyLoadError):
            keys._read_key_ref("-----BEGIN nothing")
        with self.assertRaises(keys.KeyLoadError):
            keys.load_public_key("/definitely/not/a/key.pub")
        with self.assertRaises(keys.KeyLoadError):
            keys.load_public_key("-----BEGIN PUBLIC KEY-----\nbroken\n")
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "garbage.pub"
            path.write_text("not a key")
            with self.assertRaises(keys.KeyLoadError):
                keys.load_public_key(str(path))

    def test_detect_key_algorithm_fallbacks(self) -> None:
        assert keys.detect_key_algorithm("not pem") == "unknown"
        k1 = ec.generate_private_key(ec.SECP256K1())
        assert keys.detect_key_algorithm(keys.public_key_pem(k1)) == "ECDSA"
        p384 = ec.generate_private_key(ec.SECP384R1())
        assert keys.detect_key_algorithm(keys.public_key_pem(p384)) == "ECDSA-P-384"

    def test_public_key_pem_accepts_public_keys(self) -> None:
        key = ed25519.Ed25519PrivateKey.generate()
        assert keys.public_key_pem(key.public_key()) == keys.public_key_pem(key)


class TestEd25519phEdgeCases(unittest.TestCase):
    def test_invalid_inputs_are_rejected(self) -> None:
        seed = os.urandom(32)
        pub = ed25519ph.public_key(seed)
        sig = ed25519ph.sign(seed, b"msg")
        assert ed25519ph.verify(pub, b"msg", sig)
        assert not ed25519ph.verify(pub, b"other", sig)
        assert not ed25519ph.verify(pub[:31], b"msg", sig)
        assert not ed25519ph.verify(pub, b"msg", sig[:63])
        # Non-canonical scalar (s >= L).
        big_s = (2**252 + 27742317777372353535851937790883648493).to_bytes(32, "little")
        assert not ed25519ph.verify(pub, b"msg", sig[:32] + big_s)
        with self.assertRaises(ValueError):
            ed25519ph.sign(b"short", b"msg")
        with self.assertRaises(ValueError):
            ed25519ph.public_key(b"short")


class ScriptedStore(FakeStore):
    """FakeStore with injectable failures and extra referrer responses."""

    def __init__(self) -> None:
        super().__init__()
        self.extra: list[store_v1.PullReferrerResponse] = []
        self.push_failures: list[int] = []
        self.pull_error: Exception | None = None
        self.lookup_error: Exception | None = None
        self._push_calls = 0

    def push_referrer(
        self,
        req: list[store_v1.PushReferrerRequest],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> list[store_v1.PushReferrerResponse]:
        self._push_calls += 1
        if self._push_calls in self.push_failures:
            msg = "push boom"
            raise RuntimeError(msg)
        return super().push_referrer(req, metadata)

    def pull_referrer(
        self,
        req: list[store_v1.PullReferrerRequest],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> list[store_v1.PullReferrerResponse]:
        if self.pull_error is not None:
            raise self.pull_error
        return super().pull_referrer(req, metadata) + self.extra

    def lookup(
        self,
        refs: list[core_v1.RecordRef],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> list[core_v1.RecordMeta]:
        if self.lookup_error is not None:
            raise self.lookup_error
        return super().lookup(refs, metadata)


class TestSignVerifyEdgeCases(unittest.TestCase):
    def test_push_failures_are_reported(self) -> None:
        for failing_call, expected in ((1, "public key"), (2, "signature")):
            store = ScriptedStore()
            store.push_failures = [failing_call]
            with self.subTest(expected), self.assertRaises(RuntimeError) as ctx:
                sign_record(store, _key_sign_request(COSIGN_KEY, b"pw"))
            assert f"failed to store {expected}" in str(ctx.exception)

    def test_sign_with_oidc_provider(self) -> None:
        store = ScriptedStore()
        req = sign_v1.SignRequest(
            record_ref=core_v1.RecordRef(cid=CID),
            provider=sign_v1.SignRequestProvider(
                oidc=sign_v1.SignWithOIDC(id_token="token")
            ),
        )
        signature = sign_v1.Signature(signature="c2ln", content_bundle="{}")
        with unittest.mock.patch.object(
            oidc,
            "sign_blob_with_oidc",
            return_value=(signature, sign_v1.PublicKey(key="pem")),
        ) as signer:
            sign_record(store, req)
        signer.assert_called_once()
        assert len(store.pushed) == 2

        with (
            unittest.mock.patch.object(
                oidc, "sign_blob_with_oidc", side_effect=oidc.OIDCError("nope")
            ),
            self.assertRaises(RuntimeError) as ctx,
        ):
            sign_record(ScriptedStore(), req)
        assert "failed to sign record" in str(ctx.exception)

    def test_unusable_referrers_are_skipped(self) -> None:
        store = ScriptedStore()
        sign_record(store, _key_sign_request(COSIGN_KEY, b"pw"))
        store.extra = [
            store_v1.PullReferrerResponse(),  # no referrer set
            store_v1.PullReferrerResponse(
                referrer=core_v1.RecordReferrer(
                    type="x", data={"signature": [1], "key": [1]}
                )
            ),
        ]
        ref = core_v1.RecordRef(cid=CID)
        assert len(verify_mod.pull_signatures(store, ref)) == 1
        assert verify_mod.pull_public_keys(store, ref) == [COSIGN_PUB]
        response = verify_record(store, sign_v1.VerifyRequest(record_ref=ref))
        assert response.success

    def test_lookup_errors(self) -> None:
        req = sign_v1.VerifyRequest(record_ref=core_v1.RecordRef(cid=CID))

        class GrpcLikeError(Exception):
            def details(self) -> str:
                return "record not found in store"

        store = ScriptedStore()
        store.lookup_error = GrpcLikeError()
        response = verify_record(store, req)
        assert response.error_message == "record not found"

        store.lookup_error = ConnectionError("down")
        with self.assertRaises(RuntimeError) as ctx:
            verify_record(store, req)
        assert "failed to lookup record" in str(ctx.exception)

    def test_pull_failures(self) -> None:
        store = ScriptedStore()
        store.pull_error = ConnectionError("down")
        req = sign_v1.VerifyRequest(record_ref=core_v1.RecordRef(cid=CID))
        with self.assertRaises(RuntimeError) as ctx:
            verify_record(store, req)
        assert "pull signatures" in str(ctx.exception)

        # Signatures succeed but the public key lookup fails.
        signed = ScriptedStore()
        sign_record(signed, _key_sign_request(COSIGN_KEY, b"pw"))
        original = signed.pull_referrer

        def flaky(
            req: list[store_v1.PullReferrerRequest],
            metadata: Sequence[tuple[str, str]] | None = None,
        ) -> list[store_v1.PullReferrerResponse]:
            if req[0].referrer_type == referrer.PUBLIC_KEY_REFERRER_TYPE:
                msg = "keys down"
                raise ConnectionError(msg)
            return original(req, metadata)

        signed.pull_referrer = flaky  # type: ignore[method-assign]
        with self.assertRaises(RuntimeError) as ctx:
            verify_record(signed, req)
        assert "pull public keys" in str(ctx.exception)

    def test_verify_with_fetcher_requires_cid(self) -> None:
        with self.assertRaises(ValueError):
            verify_mod.verify_with_fetcher(ScriptedStore(), sign_v1.VerifyRequest())

    def test_verify_with_keys_edge_cases(self) -> None:
        raw = base64.b64decode(COSIGN_BLOB_SIGNATURE)
        payload = b"bafytestcid"
        good = sign_v1.Signature(signature=COSIGN_BLOB_SIGNATURE)
        # Unloadable keys are skipped; the next key still verifies.
        info = verify_mod._verify_with_keys(payload, ["not a key", COSIGN_PUB], good)
        assert info.key.public_key == COSIGN_PUB
        # A signature that is not base64 is treated as raw bytes and rejected.
        with self.assertRaises(ValueError):
            verify_mod._verify_with_keys(
                payload, [COSIGN_PUB], sign_v1.Signature(signature="@@not-base64@@")
            )
        assert len(raw) > 0

    def test_verify_with_any_errors(self) -> None:
        options = sign_v1.VerifyOptionsOIDC()
        no_key = sign_v1.Signature(signature=COSIGN_BLOB_SIGNATURE)
        with self.assertRaises(ValueError) as ctx:
            verify_mod._verify_with_any(b"other", [COSIGN_PUB], no_key, options)
        assert "failed to verify signature with keys" in str(ctx.exception)

        bundled = sign_v1.Signature(signature="c2ln", content_bundle="not json")
        with self.assertRaises(ValueError) as ctx:
            verify_mod._verify_with_any(b"x", [], bundled, options)
        assert "failed to verify signature with OIDC" in str(ctx.exception)

    def test_signer_key(self) -> None:
        assert verify_mod._signer_key(sign_v1.SignerInfo()) == ""
        key_signer = sign_v1.SignerInfo(key=sign_v1.SignerInfoKey(public_key="k"))
        oidc_signer = sign_v1.SignerInfo(oidc=sign_v1.SignerInfoOIDC(issuer="i"))
        assert verify_mod._signer_key(key_signer).startswith("key:")
        assert verify_mod._signer_key(oidc_signer).startswith("oidc:")


class _Certs:
    """Helpers building small throwaway certificates."""

    @staticmethod
    def build(
        extensions: Sequence[tuple[x509.ExtensionType, bool]] = (),
        key: object | None = None,
    ) -> x509.Certificate:
        key = key or ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(
                x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ca")])
            )
            .public_key(key.public_key())  # type: ignore[attr-defined]
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(minutes=10))
        )
        for extension, critical in extensions:
            builder = builder.add_extension(extension, critical)
        algorithm = (
            None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
        )
        return builder.sign(key, algorithm)  # type: ignore[arg-type]


class TestOIDCEdgeCases(unittest.TestCase):
    def test_der_utf8_string(self) -> None:
        assert oidc._der_utf8_string(b"\x0c\x03abc") == "abc"
        long_value = "a" * 200
        encoded = b"\x0c\x81" + bytes([200]) + long_value.encode()
        assert oidc._der_utf8_string(encoded) == long_value
        for bad in (b"", b"\x04\x01a"):
            with self.assertRaises(oidc.OIDCError):
                oidc._der_utf8_string(bad)

    def test_summarize_certificate_variants(self) -> None:
        issuer_v1 = x509.UnrecognizedExtension(oidc._OID_ISSUER_V1, b"https://v1")
        email = x509.SubjectAlternativeName([x509.RFC822Name("dev@example.com")])
        summary = oidc._summarize_certificate(
            _Certs.build([(issuer_v1, False), (email, True)])
        )
        assert (summary.issuer, summary.subject) == ("https://v1", "dev@example.com")

        other = x509.SubjectAlternativeName(
            [x509.OtherName(oidc._OID_OTHER_NAME_SAN, b"\x0c\x04user")]
        )
        summary = oidc._summarize_certificate(_Certs.build([(other, True)]))
        assert summary.subject == "user"

        unrelated = x509.SubjectAlternativeName([x509.DNSName("example.com")])
        for extensions in ([], [(unrelated, True)]):
            with self.assertRaises(oidc.OIDCError):
                oidc._summarize_certificate(_Certs.build(extensions))

    def test_matches(self) -> None:
        assert oidc._matches("", ".*", "anything")
        assert oidc._matches("exact", "", "exact")
        assert not oidc._matches("exact", "", "different")
        assert not oidc._matches("", "^a", "b")

    def test_verify_signature_key_types(self) -> None:
        digest = hashlib.sha256(b"payload").digest()
        ec_key = ec.generate_private_key(ec.SECP256R1())
        signature = ec_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        oidc._verify_signature(_Certs.build(key=ec_key), signature, digest)
        with self.assertRaises(oidc.OIDCError):
            oidc._verify_signature(_Certs.build(key=ec_key), signature, b"x" * 32)

        rsa_key = rsa.generate_private_key(65537, 2048)
        rsa_signature = rsa_key.sign(
            digest, padding.PKCS1v15(), Prehashed(hashes.SHA256())
        )
        rsa_cert = _Certs.build(key=rsa_key)
        oidc._verify_signature(rsa_cert, rsa_signature, digest)
        with self.assertRaises(oidc.OIDCError):
            oidc._verify_signature(rsa_cert, b"\x00" * 256, digest)

        with self.assertRaises(oidc.OIDCError):
            oidc._verify_signature(
                _Certs.build(key=ed25519.Ed25519PrivateKey.generate()), b"", digest
            )

    def test_load_trusted_root_errors(self) -> None:
        with self.assertRaises(oidc.OIDCError):
            oidc._load_trusted_root(
                sign_v1.VerifyOptionsOIDC(trusted_root_path="/no/such/root.json")
            )
        with (
            unittest.mock.patch.object(
                oidc, "TrustUpdater", side_effect=RuntimeError("offline")
            ),
            self.assertRaises(oidc.OIDCError) as ctx,
        ):
            oidc._load_trusted_root(sign_v1.VerifyOptionsOIDC())
        assert "TUF" in str(ctx.exception)

    def test_verify_signed_timestamp(self) -> None:
        now = datetime.now(timezone.utc)

        def authority(count: int, start: datetime, end: datetime | None) -> object:
            return SimpleNamespace(
                certificates=lambda allow_expired: [object()] * count,  # noqa: ARG005
                validity_period_start=start,
                validity_period_end=end,
            )

        class FakeBuilder:
            fail = False

            def tsa_certificate(self, _cert: object) -> FakeBuilder:
                return self

            def add_root_certificate(self, _cert: object) -> FakeBuilder:
                return self

            def add_intermediate_certificate(self, _cert: object) -> FakeBuilder:
                return self

            def build(self) -> FakeBuilder:
                return self

            def verify_message(self, _response: object, _message: bytes) -> None:
                if FakeBuilder.fail:
                    msg = "bad timestamp"
                    raise oidc.Rfc3161VerificationError(msg)

        response = SimpleNamespace(tst_info=SimpleNamespace(gen_time=now))
        day = timedelta(days=1)

        def run(*authorities: object) -> object:
            root = SimpleNamespace(get_timestamp_authorities=lambda: list(authorities))
            return oidc._verify_signed_timestamp(root, response, b"sig")  # type: ignore[arg-type]

        with unittest.mock.patch.object(oidc, "VerifierBuilder", FakeBuilder):
            FakeBuilder.fail = False
            # Too few certificates, then a valid open-ended authority.
            verified = run(authority(1, now - day, None), authority(3, now - day, None))
            assert verified is not None
            assert verified.source == "TimestampAuthority"  # type: ignore[attr-defined]
            # Timestamp outside the authority's validity period.
            assert run(authority(2, now - day, now - timedelta(hours=1))) is None
            assert run(authority(2, now + day, None)) is None
            # Verification failures move on to the next authority.
            FakeBuilder.fail = True
            assert run(authority(2, now - day, None)) is None

    def test_identity_token_interactive_flow(self) -> None:
        issuer = unittest.mock.MagicMock()
        with unittest.mock.patch.object(oidc, "Issuer", return_value=issuer) as cls:
            result = oidc._identity_token(
                "",
                sign_v1.SignOptionsOIDC(
                    oidc_provider_url="https://idp.example",
                    oidc_client_id="client",
                    oidc_client_secret="secret",
                ),
            )
        cls.assert_called_once_with("https://idp.example")
        issuer.identity_token.assert_called_once_with(
            client_id="client", client_secret="secret"
        )
        assert result is issuer.identity_token.return_value

    def test_sign_with_rekor_entry(self) -> None:
        ca_key, ca_cert = _make_ca()
        requests: list[dict[str, Any]] = []

        class FakeFulcio:
            def __init__(self, _url: str) -> None:
                self.signing_cert = self

            def post(self, csr: x509.CertificateSigningRequest, _id: object) -> object:
                public_key = csr.public_key()
                assert isinstance(public_key, ec.EllipticCurvePublicKey)
                return SimpleNamespace(
                    cert=_issue_leaf(ca_key, ca_cert, public_key, "https://x/id")
                )

        class FakeTSA:
            def __init__(self, _url: str) -> None: ...

            def request_timestamp(self, _signature: bytes) -> object:
                return SimpleNamespace(as_bytes=lambda: b"ts")

        class FakeRekor:
            def __init__(self, url: str) -> None:
                requests.append({"url": url})

            def _build_hashed_rekord_request(self, **kwargs: Any) -> str:  # noqa: ANN401
                requests.append(kwargs)
                return "request"

            def create_entry(self, request: str) -> str:
                return f"entry:{request}"

        def from_parts(*parts: object) -> object:
            requests.append({"parts": parts})
            return SimpleNamespace(
                to_json=lambda: '{"rekor": true}',
                _inner=SimpleNamespace(media_type="application/vnd.test+json"),
            )

        with (
            unittest.mock.patch.object(oidc, "FulcioClient", FakeFulcio),
            unittest.mock.patch.object(oidc, "TimestampAuthorityClient", FakeTSA),
            unittest.mock.patch.object(oidc, "RekorClient", FakeRekor),
            unittest.mock.patch.object(oidc, "IdentityToken", lambda t, **_: t),
            unittest.mock.patch.object(oidc.Bundle, "_from_parts", from_parts),
        ):
            signature, _ = oidc.sign_blob_with_oidc(
                CID.encode(),
                sign_v1.SignWithOIDC(
                    id_token="token",
                    options=sign_v1.SignOptionsOIDC(rekor_url="https://rekor.test"),
                ),
            )
        assert requests[0] == {"url": "https://rekor.test"}
        assert signature.content_bundle == '{"rekor": true}'
        assert signature.content_type == "application/vnd.test+json"
        assert requests[-1]["parts"][2] == "entry:request"

    def test_verify_bundle_variants(self) -> None:
        helper = TestOIDC("test_value_matcher")
        relaxed: dict[str, Any] = {
            "ignore_tlog": True,
            "ignore_tsa": True,
            "ignore_sct": True,
        }
        with tempfile.TemporaryDirectory() as tmp:
            signature, root_path = helper._synthetic_signature(tmp)
            bundle = json.loads(signature.content_bundle)

            def with_bundle(mutated: dict[str, Any]) -> sign_v1.Signature:
                copy = sign_v1.Signature()
                copy.CopyFrom(signature)
                copy.content_bundle = json.dumps(mutated)
                return copy

            # Bundle without a message signature.
            no_message = {k: v for k, v in bundle.items() if k != "messageSignature"}
            with self.assertRaises(oidc.OIDCError):
                helper._verify_synthetic(with_bundle(no_message), root_path, **relaxed)

            # Bundle without any certificate.
            no_cert = json.loads(signature.content_bundle)
            no_cert["verificationMaterial"].pop("certificate")
            with self.assertRaises(oidc.OIDCError):
                helper._verify_synthetic(with_bundle(no_cert), root_path, **relaxed)

            # Pre-v0.3 style certificate chain.
            chain = json.loads(signature.content_bundle)
            leaf = chain["verificationMaterial"].pop("certificate")
            chain["verificationMaterial"]["x509CertificateChain"] = {
                "certificates": [leaf]
            }
            info = helper._verify_synthetic(with_bundle(chain), root_path, **relaxed)
            assert info.oidc.issuer == "https://issuer.example"

            # A recorded digest that does not match the payload.
            bad_digest = json.loads(signature.content_bundle)
            bad_digest["messageSignature"]["messageDigest"]["digest"] = (
                base64.b64encode(b"\x00" * 32).decode()
            )
            with self.assertRaises(oidc.OIDCError):
                helper._verify_synthetic(with_bundle(bad_digest), root_path, **relaxed)

            # A required transparency log entry that is missing.
            with self.assertRaises(oidc.OIDCError) as ctx:
                helper._verify_synthetic(
                    signature, root_path, ignore_tsa=True, ignore_sct=True
                )
            assert "log inclusion" in str(ctx.exception)

            # Without any usable time source nothing can be verified.
            with self.assertRaises(oidc.OIDCError):
                helper._verify_synthetic(
                    signature,
                    root_path,
                    ignore_tsa=True,
                    ignore_sct=True,
                    ignore_tlog=False,
                )

    def test_verify_timestamps_and_sct_failures(self) -> None:
        helper = TestOIDC("test_value_matcher")
        with tempfile.TemporaryDirectory() as tmp:
            signature, root_path = helper._synthetic_signature(tmp)
            # With the log ignored, an SCT is still required and absent.
            with self.assertRaises(oidc.OIDCError) as ctx:
                helper._verify_synthetic(
                    signature, root_path, ignore_tlog=True, ignore_tsa=True
                )
            assert "signed certificate timestamp" in str(ctx.exception)
            # A timestamp is required and absent.
            with self.assertRaises(oidc.OIDCError) as ctx:
                helper._verify_synthetic(
                    signature, root_path, ignore_tlog=True, ignore_sct=True
                )
            assert "timestamps" in str(ctx.exception)


if __name__ == "__main__":
    unittest.main()
