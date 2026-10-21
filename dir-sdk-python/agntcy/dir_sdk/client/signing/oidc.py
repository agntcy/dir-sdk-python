# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Keyless (OIDC / Sigstore bundle) signing and verification.

Mirrors the Go client (``client/utils/cosign``) on top of the ``sigstore``
Python package: signing produces a Sigstore bundle with an ephemeral key, a
Fulcio certificate, an optional Rekor entry and RFC 3161 timestamps; verification
follows the sigstore-go verifier configuration used by the Go client.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

from agntcy.dir_sdk.models import sign_v1
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from OpenSSL.crypto import (
    X509,
    X509Store,
    X509StoreContext,
    X509StoreContextError,
    X509StoreFlags,
)
from rfc3161_client import TimeStampResponse, VerifierBuilder
from rfc3161_client import VerificationError as Rfc3161VerificationError
from sigstore._internal.fulcio.client import FulcioClient
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.sct import verify_sct
from sigstore._internal.timestamp import TimestampAuthorityClient
from sigstore._internal.trust import KeyringPurpose
from sigstore._internal.tuf import TrustUpdater
from sigstore._utils import sha256_digest
from sigstore.errors import Error as SigstoreError
from sigstore.models import Bundle, TimestampVerificationData, TrustedRoot
from sigstore.oidc import IdentityToken, Issuer
from sigstore.verify.verifier import (
    _validate_hashedrekord_v001_entry_body,
    _validate_hashedrekord_v002_entry_body,
)
from sigstore_models.bundle import v1 as bundle_v1
from sigstore_models.common import v1 as common_v1
from sigstore_models.common.v1 import HashOutput, MessageSignature

logger = logging.getLogger("client")

DEFAULT_FULCIO_URL = "https://fulcio.sigstore.dev"
DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
DEFAULT_TIMESTAMP_URL = "https://timestamp.sigstore.dev/api/v1/timestamp"
DEFAULT_TUF_MIRROR_URL = "https://tuf-repo-cdn.sigstore.dev"
DEFAULT_OIDC_PROVIDER_URL = "https://oauth2.sigstore.dev/auth"
DEFAULT_OIDC_CLIENT_ID = "sigstore"

_OID_ISSUER_V1 = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
_OID_ISSUER_V2 = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.8")
_OID_OTHER_NAME_SAN = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.7")

_UTF8_STRING_TAG = 0x0C
_DER_LONG_FORM = 0x80


class OIDCError(Exception):
    """Raised for keyless signing and verification failures."""


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def _identity_token(id_token: str, opts: sign_v1.SignOptionsOIDC) -> IdentityToken:
    client_id = opts.oidc_client_id or DEFAULT_OIDC_CLIENT_ID
    if id_token:
        return IdentityToken(id_token, client_id=client_id)
    # No token supplied: run the interactive OIDC flow against the provider.
    issuer = Issuer(opts.oidc_provider_url or DEFAULT_OIDC_PROVIDER_URL)
    return issuer.identity_token(
        client_id=client_id, client_secret=opts.oidc_client_secret
    )


def sign_blob_with_oidc(
    payload: bytes,
    req: sign_v1.SignWithOIDC,
) -> tuple[sign_v1.Signature, sign_v1.PublicKey]:
    """Sign payload with an ephemeral key and a Fulcio certificate."""
    signing_time = datetime.now(timezone.utc)
    opts = req.options
    fulcio_url = opts.fulcio_url or DEFAULT_FULCIO_URL
    rekor_url = opts.rekor_url or DEFAULT_REKOR_URL
    timestamp_url = opts.timestamp_url or DEFAULT_TIMESTAMP_URL

    try:
        identity = _identity_token(req.id_token, opts)

        key = ec.generate_private_key(ec.SECP256R1())
        public_key_pem = key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

        # Fulcio takes the identity from the OIDC token, the CSR subject is unused.
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([]))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .sign(key, hashes.SHA256())
        )
        certificate = FulcioClient(fulcio_url).signing_cert.post(csr, identity).cert

        hashed = sha256_digest(payload)
        raw_signature = key.sign(hashed.digest, ec.ECDSA(hashed._as_prehashed()))
        content = MessageSignature(
            message_digest=HashOutput(
                algorithm=hashed.algorithm,
                digest=base64.b64encode(hashed.digest),
            ),
            signature=base64.b64encode(raw_signature),
        )

        timestamps = [
            TimestampAuthorityClient(timestamp_url).request_timestamp(raw_signature)
        ]

        if opts.skip_tlog:
            bundle_json = _bundle_without_tlog(certificate, content, timestamps)
            media_type = Bundle.BundleType.BUNDLE_0_3.value
        else:
            rekor = RekorClient(rekor_url)
            entry = rekor.create_entry(
                rekor._build_hashed_rekord_request(
                    hashed_input=hashed,
                    signature=raw_signature,
                    certificate=certificate,
                )
            )
            bundle = Bundle._from_parts(certificate, content, entry, timestamps)
            bundle_json = bundle.to_json()
            media_type = bundle._inner.media_type
    except Exception as e:
        msg = f"failed to sign record: {e}"
        raise OIDCError(msg) from e

    signature = sign_v1.Signature(
        signature=base64.b64encode(raw_signature).decode("ascii"),
        certificate=base64.b64encode(certificate.public_bytes(Encoding.DER)).decode(
            "ascii"
        ),
        content_type=str(media_type),
        content_bundle=bundle_json,
        signed_at=signing_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    return signature, sign_v1.PublicKey(key=public_key_pem.decode("ascii"))


def _bundle_without_tlog(
    certificate: x509.Certificate,
    content: MessageSignature,
    timestamps: Sequence[TimeStampResponse],
) -> str:
    """Build a v0.3 bundle without a transparency log entry (skip_tlog)."""
    inner = bundle_v1.Bundle(
        media_type=Bundle.BundleType.BUNDLE_0_3.value,
        verification_material=bundle_v1.VerificationMaterial(
            certificate=common_v1.X509Certificate(
                raw_bytes=base64.b64encode(certificate.public_bytes(Encoding.DER))
            ),
            tlog_entries=[],
            timestamp_verification_data=bundle_v1.TimestampVerificationData(
                rfc3161_timestamps=[
                    common_v1.RFC3161SignedTimestamp(
                        signed_timestamp=base64.b64encode(ts.as_bytes())
                    )
                    for ts in timestamps
                ]
            ),
        ),
        message_signature=content,
    )
    return inner.to_json()


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _VerifiedTime:
    source: str
    time: datetime


def _load_trusted_root(opts: sign_v1.VerifyOptionsOIDC) -> TrustedRoot:
    if opts.trusted_root_path:
        try:
            return TrustedRoot.from_file(opts.trusted_root_path)
        except Exception as e:
            msg = f"failed to load trusted root from path {opts.trusted_root_path}: {e}"
            raise OIDCError(msg) from e

    tuf_url = opts.tuf_mirror_url or DEFAULT_TUF_MIRROR_URL
    try:
        updater = TrustUpdater(tuf_url)
        return TrustedRoot.from_file(updater.get_trusted_root_path())
    except Exception as e:
        msg = f"failed to fetch trusted root from TUF: {e}"
        raise OIDCError(msg) from e


def _verify_signed_timestamp(
    trusted_root: TrustedRoot,
    response: TimeStampResponse,
    message: bytes,
) -> _VerifiedTime | None:
    for authority in trusted_root.get_timestamp_authorities():
        certificates = authority.certificates(allow_expired=True)
        # A signing certificate and a root are required, intermediates optional.
        if len(certificates) < 2:
            continue

        builder = (
            VerifierBuilder()
            .tsa_certificate(certificates[0])
            .add_root_certificate(certificates[-1])
        )
        for intermediate in certificates[1:-1]:
            builder = builder.add_intermediate_certificate(intermediate)
        try:
            builder.build().verify_message(response, message)
        except Rfc3161VerificationError:
            continue

        gen_time = response.tst_info.gen_time
        end = authority.validity_period_end
        if authority.validity_period_start <= gen_time and (
            end is None or gen_time < end
        ):
            return _VerifiedTime("TimestampAuthority", gen_time)
    return None


def _verify_chain_at_time(
    trusted_root: TrustedRoot,
    leaf: x509.Certificate,
    intermediates: Sequence[x509.Certificate],
    at: datetime,
) -> list[x509.Certificate]:
    store = X509Store()
    store.set_flags(X509StoreFlags.X509_STRICT)
    for ca in trusted_root.get_fulcio_certs():
        store.add_cert(X509.from_cryptography(ca))
    store.set_time(at)
    context = X509StoreContext(
        store,
        X509.from_cryptography(leaf),
        chain=[X509.from_cryptography(c) for c in intermediates],
    )
    try:
        verified = context.get_verified_chain()
    except X509StoreContextError as e:
        msg = f"failed to verify leaf certificate: {e}"
        raise OIDCError(msg) from e
    return [c.to_cryptography() for c in verified[1:]]


def _der_utf8_string(data: bytes) -> str:
    if len(data) < 2 or data[0] != _UTF8_STRING_TAG:
        msg = "unexpected OtherName encoding"
        raise OIDCError(msg)
    length = data[1]
    offset = 2
    if length & _DER_LONG_FORM:
        count = length & ~_DER_LONG_FORM
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    return data[offset : offset + length].decode("utf-8")


@dataclass(frozen=True)
class _CertSummary:
    issuer: str
    subject: str
    certificate_issuer: str


def _summarize_certificate(cert: x509.Certificate) -> _CertSummary:
    issuer = ""
    for ext in cert.extensions:
        raw = (
            ext.value.value
            if isinstance(ext.value, x509.UnrecognizedExtension)
            else b""
        )
        if ext.oid == _OID_ISSUER_V1 and not issuer:
            issuer = raw.decode("utf-8", errors="replace")
        elif ext.oid == _OID_ISSUER_V2:
            issuer = _der_utf8_string(raw)

    subject = ""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san = None
    if san is not None:
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        emails = san.get_values_for_type(x509.RFC822Name)
        if uris:
            subject = uris[0]
        elif emails:
            subject = emails[0]
        else:
            for other in san.get_values_for_type(x509.OtherName):
                if other.type_id == _OID_OTHER_NAME_SAN:
                    subject = _der_utf8_string(other.value)
                    break
    if not subject:
        msg = "no Subject Alternative Name found"
        raise OIDCError(msg)

    return _CertSummary(
        issuer=issuer,
        subject=subject,
        certificate_issuer=cert.issuer.rfc4514_string(),
    )


def get_value_matcher(value: str) -> tuple[str, str]:
    """Return (exact, regexp) matchers for value, as the Go client does."""
    if value == "":
        return "", ".*"
    try:
        re.compile(value)
    except re.error:
        return value, ""
    return "", value


def _matches(exact: str, pattern: str, actual: str) -> bool:
    if exact and actual != exact:
        return False
    return not (pattern and re.search(pattern, actual) is None)


def _verify_signature(cert: x509.Certificate, signature: bytes, digest: bytes) -> None:
    key = cert.public_key()
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(
                signature, digest, padding.PKCS1v15(), Prehashed(hashes.SHA256())
            )
        else:
            msg = f"unsupported certificate public key type: {type(key).__name__}"
            raise OIDCError(msg)
    except InvalidSignature as e:
        msg = "failed to verify signature: signature is invalid for input"
        raise OIDCError(msg) from e


def verify_with_oidc(
    payload: bytes,
    req: sign_v1.VerifyWithOIDC,
    signature: sign_v1.Signature,
) -> sign_v1.SignerInfo:
    """Verify a Sigstore bundle against the OIDC identity in req."""
    opts = req.options if req.HasField("options") else sign_v1.VerifyOptionsOIDC()

    try:
        bundle_inner = bundle_v1.Bundle.from_json(signature.content_bundle)
    except Exception as e:
        msg = f"failed to parse bundle: {e}"
        raise OIDCError(msg) from e

    trusted_root = _load_trusted_root(opts)

    material = bundle_inner.verification_material
    if bundle_inner.message_signature is None:
        msg = "failed to verify signature: bundle has no message signature"
        raise OIDCError(msg)
    raw_signature = bundle_inner.message_signature.signature

    # Leaf certificate (and intermediates for pre-v0.3 bundles).
    intermediates: list[x509.Certificate] = []
    if material.certificate is not None:
        leaf = x509.load_der_x509_certificate(material.certificate.raw_bytes)
    elif (
        material.x509_certificate_chain and material.x509_certificate_chain.certificates
    ):
        certs = [
            x509.load_der_x509_certificate(c.raw_bytes)
            for c in material.x509_certificate_chain.certificates
        ]
        leaf, intermediates = certs[0], certs[1:]
    else:
        msg = "bundle does not contain a signing certificate"
        raise OIDCError(msg)

    digest = hashlib.sha256(payload).digest()
    if (
        bundle_inner.message_signature.message_digest is not None
        and bundle_inner.message_signature.message_digest.digest != digest
    ):
        msg = "failed to verify signature: message digest mismatch"
        raise OIDCError(msg)

    # Transparency log (required unless ignore_tlog).
    if not opts.ignore_tlog:
        try:
            bundle = Bundle(bundle_inner)
            entry = bundle.log_entry
            entry._verify(trusted_root.rekor_keyring(KeyringPurpose.VERIFY))
            hashed = sha256_digest(payload)
            version = entry._inner.kind_version.version
            if entry._inner.kind_version.kind != "hashedrekord":
                msg = f"expected entry type hashedrekord, got {entry._inner.kind_version.kind}"
                raise OIDCError(msg)
            if version == "0.0.2":
                _validate_hashedrekord_v002_entry_body(bundle, hashed)
            else:
                _validate_hashedrekord_v001_entry_body(bundle, hashed)
        except (SigstoreError, ValueError, KeyError) as e:
            msg = f"failed to verify log inclusion: {e}"
            raise OIDCError(msg) from e
        except OIDCError:
            raise

    # Observer timestamps.
    verified_times: list[_VerifiedTime] = []
    if not opts.ignore_tsa:
        responses = (
            TimestampVerificationData(
                material.timestamp_verification_data
            ).rfc3161_timestamps
            if material.timestamp_verification_data is not None
            else []
        )
        for response in responses:
            verified = _verify_signed_timestamp(trusted_root, response, raw_signature)
            if verified is not None:
                verified_times.append(verified)
        if not verified_times:
            msg = "failed to verify timestamps: threshold not met for verified signed timestamps: 0 < 1"
            raise OIDCError(msg)
    if opts.ignore_tlog:
        verified_times.append(_VerifiedTime("CurrentTime", datetime.now(timezone.utc)))
    if not verified_times:
        msg = "failed to verify timestamps: no valid observer timestamps found"
        raise OIDCError(msg)

    # Certificate chain must validate at every verified time.
    chain: list[x509.Certificate] = []
    summary = _summarize_certificate(leaf)
    for verified_time in verified_times:
        chain = _verify_chain_at_time(
            trusted_root, leaf, intermediates, verified_time.time
        )

    if not opts.ignore_sct:
        try:
            verify_sct(leaf, chain, trusted_root.ct_keyring(KeyringPurpose.VERIFY))
        except (SigstoreError, ValueError) as e:
            msg = f"failed to verify signed certificate timestamp: {e}"
            raise OIDCError(msg) from e

    _verify_signature(leaf, raw_signature, digest)

    # Identity policy.
    issuer, issuer_regexp = get_value_matcher(req.issuer)
    subject, subject_regexp = get_value_matcher(req.subject)
    if not _matches(issuer, issuer_regexp, summary.issuer):
        msg = f"failed to verify certificate identity: no matching issuer, got {summary.issuer!r}"
        raise OIDCError(msg)
    if not _matches(subject, subject_regexp, summary.subject):
        msg = f"failed to verify certificate identity: no matching subject alternative name, got {summary.subject!r}"
        raise OIDCError(msg)

    return sign_v1.SignerInfo(
        oidc=sign_v1.SignerInfoOIDC(
            issuer=summary.issuer,
            subject=summary.subject,
            certificate_issuer=summary.certificate_issuer,
        )
    )
