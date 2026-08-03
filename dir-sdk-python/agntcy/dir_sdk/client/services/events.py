# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Events service wrappers."""

from __future__ import annotations

import logging
from collections.abc import Sequence

import grpc
from agntcy.dir_sdk.client.services.base import RpcServiceBase
from agntcy.dir_sdk.models import events_v1


class EventService(RpcServiceBase):
    def __init__(
        self, event_client: events_v1.EventServiceStub, logger: logging.Logger
    ) -> None:
        super().__init__(logger)
        self._event_client = event_client

    def listen(
        self,
        req: events_v1.ListenRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> grpc.UnaryStreamMultiCallable:
        try:
            return self._event_client.Listen(req, metadata=metadata)
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.CANCELLED:
                self._logger.exception("gRPC listen stream was canceled")
            else:
                self._logger.exception("gRPC error during listen")
            raise
        except Exception as e:
            self._logger.exception("Unexpected error during listen")
            msg = f"Failed to listen: {e}"
            raise RuntimeError(msg) from e
