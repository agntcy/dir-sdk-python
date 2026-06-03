# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Sign/verify service wrappers."""

from __future__ import annotations

from collections.abc import Sequence

import grpc

from agntcy.dir_sdk.client.config import Config
from agntcy.dir_sdk.client.dirctl.signing import sign_record
from agntcy.dir_sdk.client.dirctl.verification import verify_record
from agntcy.dir_sdk.client.services.base import RpcServiceBase
from agntcy.dir_sdk.models import sign_v1


class SignService(RpcServiceBase):
    def __init__(
        self, config: Config, sign_client: sign_v1.SignServiceStub, logger
    ) -> None:
        super().__init__(logger)
        self._config = config
        self._sign_client = sign_client

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
                self._logger.exception("gRPC error during verify: %s", e)
                raise RuntimeError(f"Verify failed: {e}") from e
            except Exception as e:
                self._logger.exception("Verification failed: %s", e)
                raise RuntimeError(f"Verify failed: {e}") from e
        try:
            return verify_record(self._config, req)
        except Exception as e:
            self._logger.exception("Verification operation failed: %s", e)
            raise RuntimeError(f"Failed to verify the object: {e}") from e

    def sign(self, req: sign_v1.SignRequest) -> None:
        try:
            sign_record(self._config, req)
        except RuntimeError as e:
            raise RuntimeError(f"Failed to sign the object: {e}") from e
        except Exception as e:
            self._logger.exception("Signing operation failed: %s", e)
            raise RuntimeError(f"Failed to sign the object: {e}") from e
