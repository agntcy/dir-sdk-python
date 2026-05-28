# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""dirctl command execution helpers."""

from agntcy.dir_sdk.client.dirctl.signing import sign_record
from agntcy.dir_sdk.client.dirctl.verification import verify_record

__all__ = ["sign_record", "verify_record"]
