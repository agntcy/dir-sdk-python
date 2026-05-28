# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Naming service wrappers."""

from __future__ import annotations

from collections.abc import Sequence

from agntcy.dir_sdk.client.services.base import RpcServiceBase
from agntcy.dir_sdk.models import naming_v1


class NamingService(RpcServiceBase):
    def __init__(self, naming_client: naming_v1.NamingServiceStub, logger) -> None:
        super().__init__(logger)
        self._naming_client = naming_client

    def resolve(
        self,
        name: str,
        version: str | None = None,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> naming_v1.ResolveResponse:
        def call():
            req = naming_v1.ResolveRequest(name=name)
            if version:
                req.version = version
            return self._naming_client.Resolve(req, metadata=metadata)

        return self._invoke("resolve", "Failed to resolve name", call)

    def get_verification_info(
        self,
        cid: str | None = None,
        name: str | None = None,
        version: str | None = None,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> naming_v1.GetVerificationInfoResponse:
        def call():
            req = naming_v1.GetVerificationInfoRequest()
            if cid:
                req.cid = cid
            if name:
                req.name = name
            if version:
                req.version = version
            return self._naming_client.GetVerificationInfo(req, metadata=metadata)

        return self._invoke(
            "get_verification_info",
            "Failed to get verification info",
            call,
        )
