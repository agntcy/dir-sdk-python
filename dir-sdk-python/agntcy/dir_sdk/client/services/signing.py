# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Sign/verify service wrappers."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence

import grpc
from agntcy.dir_sdk.client.config import Config
from agntcy.dir_sdk.client.native import sign_record, verify_record
from agntcy.dir_sdk.client.services.base import RpcServiceBase
from agntcy.dir_sdk.models import sign_v1


class SignService(RpcServiceBase):
    def __init__(
        self,
        config: Config,
        sign_client: sign_v1.SignServiceStub,
        logger: logging.Logger,
        token_provider: Callable[[], str] | None = None,
    ) -> None:
        super().__init__(logger)
        self._config = config
        self._token_provider = token_provider
        self._sign_client = sign_client

    def _auth_token(self) -> str:
        return self._token_provider() if self._token_provider else ""

    def verify(
        self,
        req: sign_v1.VerifyRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> sign_v1.VerifyResponse:
        if req.from_server:
            if req.record_ref is None or not req.record_ref.cid:
                msg = "VerifyRequest.record_ref with cid is required"
                raise RuntimeError(msg)
            try:
                return self._sign_client.Verify(req, metadata=metadata or ())
            except grpc.RpcError as e:
                self._logger.exception("gRPC error during verify")
                raise RuntimeError(f"Verify failed: {e}") from e
            except Exception as e:
                self._logger.exception("Verification failed")
                raise RuntimeError(f"Verify failed: {e}") from e
        try:
            return verify_record(self._config, req, self._auth_token())
        except Exception as e:
            self._logger.exception("Verification operation failed")
            raise RuntimeError(f"Failed to verify the object: {e}") from e

    def sign(self, req: sign_v1.SignRequest) -> None:
        try:
            sign_record(self._config, req, self._auth_token())
        except RuntimeError as e:
            raise RuntimeError(f"Failed to sign the object: {e}") from e
        except Exception as e:
            self._logger.exception("Signing operation failed")
            raise RuntimeError(f"Failed to sign the object: {e}") from e
