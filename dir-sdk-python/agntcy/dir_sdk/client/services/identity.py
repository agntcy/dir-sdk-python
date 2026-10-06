# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Identity service wrappers."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from agntcy.dir_sdk.client.services.base import RpcServiceBase
from agntcy.dir_sdk.models import identity_v1

# The reported method for a record resolved through a verified owner claim.
_OWNER_CLAIM_METHOD = "owner-claim"


class IdentityService(RpcServiceBase):
    def __init__(
        self, identity_client: identity_v1.IdentityServiceStub, logger: logging.Logger
    ) -> None:
        super().__init__(logger)
        self._identity_client = identity_client

    def resolve(
        self,
        name: str,
        version: str | None = None,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> identity_v1.ResolveResponse:
        def call() -> identity_v1.ResolveResponse:
            req = identity_v1.ResolveRequest(name=name)
            if version:
                req.version = version
            return self._identity_client.Resolve(req, metadata=metadata)

        return self._invoke("resolve", "Failed to resolve name", call)

    def get_verification_info(
        self,
        cid: str | None = None,
        name: str | None = None,
        version: str | None = None,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> identity_v1.GetVerificationInfoResponse:
        def call() -> identity_v1.GetVerificationInfoResponse:
            req = identity_v1.GetIdentityStatusRequest()
            if cid:
                req.cid = cid
            if name:
                req.name = name
            if version:
                req.version = version
            status = self._identity_client.GetIdentityStatus(req, metadata=metadata)
            return _verification_info(status)

        return self._invoke(
            "get_verification_info",
            "Failed to get verification info",
            call,
        )


def _verification_info(
    status: identity_v1.GetIdentityStatusResponse,
) -> identity_v1.GetVerificationInfoResponse:
    """Projects the ownership claim result onto the legacy result shape."""
    owner = status.owner
    if not status.HasField("owner"):
        return identity_v1.GetVerificationInfoResponse(
            error_message="no verification found"
        )

    if owner.status != identity_v1.CLAIM_VERIFICATION_STATUS_VERIFIED:
        return identity_v1.GetVerificationInfoResponse(
            error_message=owner.error or "verification failed"
        )

    return identity_v1.GetVerificationInfoResponse(
        verified=True,
        verification=identity_v1.Verification(
            domain=identity_v1.DomainVerification(
                domain=owner.subject,
                method=_OWNER_CLAIM_METHOD,
                verified_at=owner.verified_at,
            )
        ),
    )
