# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Local signature verification for Directory records."""

from __future__ import annotations

import base64
import re

from agntcy.dir_sdk.client.services.store import StoreService
from agntcy.dir_sdk.client.signing.cosign_keys import (
    detect_key_algorithm,
    load_public_key,
)
from agntcy.dir_sdk.client.signing.fetcher import StoreFetcher
from agntcy.dir_sdk.client.signing.options import get_verify_options_oidc
from agntcy.dir_sdk.models import sign_v1
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import (
    Certificate,
    OtherName,
    RFC822Name,
    SubjectAlternativeName,
    UniformResourceIdentifier,
)
from sigstore.errors import VerificationError
from sigstore.models import Bundle, ClientTrustConfig, TrustedRoot
from sigstore.verify import Verifier
from sigstore.verify.policy import Identity, UnsafeNoOp

_OTHERNAME_OID = "1.3.6.1.4.1.57264.1.7"
_ISSUER_OID = "1.3.6.1.4.1.57264.1.8"


def _value_matchers(value: str) -> tuple[str | None, re.Pattern[str] | None]:
    if not value:
        return None, re.compile(".*")
    try:
        return None, re.compile(value)
    except re.error:
        return value, None


def _certificate_identities(cert: Certificate) -> tuple[str, set[str]]:
    issuer = ""
    for ext in cert.extensions:
        if ext.oid.dotted_string == _ISSUER_OID:
            issuer = ext.value.value.decode()

    identities: set[str] = set()
    try:
        san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
        identities.update(san_ext.get_values_for_type(RFC822Name))
        identities.update(san_ext.get_values_for_type(UniformResourceIdentifier))
        for other_name in san_ext.get_values_for_type(OtherName):
            if other_name.type_id.dotted_string == _OTHERNAME_OID:
                identities.add(other_name.value.decode())
    except Exception:
        pass

    return issuer, identities


def _matches_identity(issuer: str, subject: str, cert: Certificate) -> bool:
    cert_issuer, identities = _certificate_identities(cert)
    exact_issuer, issuer_re = _value_matchers(issuer)
    exact_subject, subject_re = _value_matchers(subject)

    issuer_ok = (exact_issuer is not None and cert_issuer == exact_issuer) or (
        issuer_re is not None and issuer_re.search(cert_issuer) is not None
    )
    subject_ok = any(
        (exact_subject is not None and identity == exact_subject)
        or (subject_re is not None and subject_re.search(identity) is not None)
        for identity in identities
    )
    return issuer_ok and subject_ok


def _verify_signature_with_key(
    public_key_ref: str,
    signature_b64: str,
    payload: bytes,
) -> str:
    public_key_pem = load_public_key(public_key_ref)
    public_key = load_pem_public_key(public_key_pem)

    try:
        signature_bytes = base64.b64decode(signature_b64)
    except (ValueError, TypeError):
        signature_bytes = signature_b64.encode("utf-8")

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature_bytes, payload, ec.ECDSA(hashes.SHA256()))
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key.verify(signature_bytes, payload)
    elif isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature_bytes, payload, padding.PKCS1v15(), hashes.SHA256())
    else:
        msg = "unsupported public key type"
        raise ValueError(msg)

    return public_key_pem.decode("utf-8")


def _verify_with_keys(
    payload: bytes,
    public_keys: list[str],
    signature: sign_v1.Signature,
) -> sign_v1.SignerInfo:
    for public_key in public_keys:
        try:
            pub_key_pem = _verify_signature_with_key(
                public_key,
                signature.signature,
                payload,
            )
            return sign_v1.SignerInfo(
                key=sign_v1.SignerInfoKey(
                    public_key=pub_key_pem,
                    algorithm=detect_key_algorithm(pub_key_pem),
                )
            )
        except (InvalidSignature, ValueError):
            continue
    msg = "no valid signature found for the provided public keys"
    raise ValueError(msg)


def _trusted_root_from_options(opts: sign_v1.VerifyOptionsOIDC) -> TrustedRoot:
    if opts.trusted_root_path:
        return TrustedRoot.from_file(str(opts.trusted_root_path))
    trust_config = ClientTrustConfig.from_tuf(opts.tuf_mirror_url, offline=False)
    return trust_config.trusted_root


def _verify_with_oidc(
    payload: bytes,
    req: sign_v1.VerifyWithOIDC,
    signature: sign_v1.Signature,
) -> sign_v1.SignerInfo:
    opts = get_verify_options_oidc(req.options)
    bundle = Bundle.from_json(signature.content_bundle)

    verifier = Verifier(trusted_root=_trusted_root_from_options(opts))
    policy: Identity | UnsafeNoOp
    if req.issuer or req.subject:
        policy = UnsafeNoOp()
    else:
        policy = Identity(identity=".*", issuer=".*")

    try:
        verifier.verify_artifact(payload, bundle, policy)
    except VerificationError as exc:
        msg = f"verification failed: {exc}"
        raise ValueError(msg) from exc

    cert = bundle.signing_certificate
    issuer, identities = _certificate_identities(cert)
    subject = next(iter(identities), "")

    if (req.issuer or req.subject) and not _matches_identity(
        req.issuer, req.subject, cert
    ):
        msg = "verification failed"
        raise ValueError(msg)

    return sign_v1.SignerInfo(
        oidc=sign_v1.SignerInfoOIDC(
            issuer=issuer,
            subject=subject,
        )
    )


def _verify_with_any(
    payload: bytes,
    public_keys: list[str],
    signature: sign_v1.Signature,
) -> sign_v1.SignerInfo:
    if not signature.content_bundle:
        return _verify_with_keys(payload, public_keys, signature)
    return _verify_with_oidc(
        payload,
        sign_v1.VerifyWithOIDC(options=get_verify_options_oidc(None)),
        signature,
    )


def _get_signer_key(signer: sign_v1.SignerInfo) -> str:
    if signer.HasField("key"):
        return f"key:{signer.key.public_key}"
    if signer.HasField("oidc"):
        return f"oidc:{signer.oidc.issuer}:{signer.oidc.subject}"
    return ""


def verify_with_fetcher(
    req: sign_v1.VerifyRequest,
    fetcher: StoreFetcher,
) -> sign_v1.VerifyResponse:
    if req.record_ref is None or not req.record_ref.cid:
        msg = "record ref is required"
        raise ValueError(msg)

    try:
        fetcher.lookup(req.record_ref)
    except LookupError:
        return sign_v1.VerifyResponse(
            success=False,
            error_message="record not found",
        )

    provider = req.provider
    if provider is None or not (
        provider.HasField("key")
        or provider.HasField("oidc")
        or provider.HasField("any")
    ):
        provider = sign_v1.VerifyRequestProvider(
            any=sign_v1.VerifyWithAny(
                oidc_options=get_verify_options_oidc(None),
            )
        )

    signatures = fetcher.pull_signatures(req.record_ref)
    if not signatures:
        return sign_v1.VerifyResponse(
            success=False,
            error_message="no signatures found",
        )

    public_keys: list[str] = []
    if provider.HasField("key"):
        public_keys = [provider.key.public_key]
    elif provider.HasField("any"):
        public_keys = fetcher.pull_public_keys(req.record_ref)

    payload = req.record_ref.cid.encode("utf-8")
    seen_keys: set[str] = set()
    signers: list[sign_v1.SignerInfo] = []

    for signature in signatures:
        try:
            if provider.HasField("oidc"):
                signer_info = _verify_with_oidc(payload, provider.oidc, signature)
            elif provider.HasField("key"):
                signer_info = _verify_with_keys(payload, public_keys, signature)
            elif provider.HasField("any"):
                signer_info = _verify_with_any(payload, public_keys, signature)
            else:
                msg = "unsupported verification provider type"
                raise ValueError(msg)
        except (InvalidSignature, ValueError, VerificationError):
            continue

        signer_key = _get_signer_key(signer_info)
        if signer_key in seen_keys:
            continue
        seen_keys.add(signer_key)
        signers.append(signer_info)

    if not signers:
        return sign_v1.VerifyResponse(
            success=False,
            error_message="no valid signatures found matching verification criteria",
        )

    return sign_v1.VerifyResponse(success=True, signers=signers)


def verify_record(
    store_service: StoreService,
    req: sign_v1.VerifyRequest,
) -> sign_v1.VerifyResponse:
    return verify_with_fetcher(req, StoreFetcher(store_service))
