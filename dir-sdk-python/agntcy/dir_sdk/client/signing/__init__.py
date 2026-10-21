# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Native (dirctl-free) record signing and verification."""

from agntcy.dir_sdk.client.signing.sign import sign_record
from agntcy.dir_sdk.client.signing.verify import verify_record

__all__ = ["sign_record", "verify_record"]
