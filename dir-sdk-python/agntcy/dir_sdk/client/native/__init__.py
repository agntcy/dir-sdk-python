# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Bindings to the Directory C-shared wrapper library (libdirwrapper)."""

from agntcy.dir_sdk.client.native.library import (
    LIBRARY_ENV_VAR,
    NativeLibrary,
    NativeLibraryError,
    load_library,
)
from agntcy.dir_sdk.client.native.signing import sign_record, verify_record

__all__ = [
    "LIBRARY_ENV_VAR",
    "NativeLibrary",
    "NativeLibraryError",
    "load_library",
    "sign_record",
    "verify_record",
]
