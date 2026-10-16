# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass

from agntcy.dir.identity.v1.claim_pb2 import *
from agntcy.dir.identity.v1.identity_service_pb2 import *
from agntcy.dir.identity.v1.identity_service_pb2_grpc import *
from google.protobuf.timestamp_pb2 import Timestamp


@dataclass
class DomainVerification:
    """Describes the verified owner of a record's name."""

    domain: str
    method: str
    verified_at: Timestamp | None = None


@dataclass
class Verification:
    """Holds the details of a verified name."""

    domain: DomainVerification | None = None


@dataclass
class GetVerificationInfoResponse:
    """The result of a name ownership lookup, projected from the record's
    ownership claim (identity.v1).
    """

    verified: bool = False
    verification: Verification | None = None
    error_message: str = ""
