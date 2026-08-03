# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Shared service-layer helpers for RPC invocation and error mapping."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from typing import TypeVar, cast

import grpc

T = TypeVar("T")


class RpcServiceBase:
    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def _invoke(self, op_name: str, error_message: str, call: Callable[[], T]) -> T:
        try:
            return cast(T, call())
        except grpc.RpcError:
            self._logger.exception("gRPC error during %s", op_name)
            raise
        except Exception as e:
            self._logger.exception("Unexpected error during %s", op_name)
            msg = f"{error_message}: {e}"
            raise RuntimeError(msg) from e

    def _collect_stream(
        self,
        op_name: str,
        error_message: str,
        stream_call: Callable[[], Iterable[T]],
    ) -> list[T]:
        return self._invoke(
            op_name,
            error_message,
            lambda: list(stream_call()),
        )
