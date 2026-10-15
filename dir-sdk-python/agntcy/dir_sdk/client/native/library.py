# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Locate and load the libdirwrapper C-shared library through ctypes.

The C ABI is JSON-in/JSON-out: every exported function returns a heap
allocated ``char*`` holding a JSON document that must be released with
``FreeCString``. :class:`NativeLibrary` hides that behind :meth:`call`.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import sys
import threading
from pathlib import Path
from typing import Any

LIBRARY_ENV_VAR = "DIR_WRAPPER_LIB"
LIBRARY_NAME = "libdirwrapper"
_BUNDLED_DIR = Path(__file__).parent / "lib"


class NativeLibraryError(RuntimeError):
    """Raised when the wrapper library cannot be found, loaded or called."""


def _platform_tag() -> tuple[str, str, str]:
    """Return (goos, goarch, extension) matching the wrapperlib build names."""
    if sys.platform == "darwin":
        goos, ext = "darwin", "dylib"
    elif sys.platform.startswith("linux"):
        goos, ext = "linux", "so"
    elif sys.platform in ("win32", "cygwin"):
        goos, ext = "windows", "dll"
    else:
        msg = f"Unsupported platform for the native Directory library: {sys.platform}"
        raise NativeLibraryError(msg)

    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        goarch = "arm64"
    elif machine in ("x86_64", "amd64"):
        goarch = "amd64"
    else:
        msg = f"Unsupported architecture for the native Directory library: {machine}"
        raise NativeLibraryError(msg)
    return goos, goarch, ext


def find_library_path() -> Path:
    override = os.environ.get(LIBRARY_ENV_VAR)
    if override:
        path = Path(override)
        if not path.is_file():
            msg = f"{LIBRARY_ENV_VAR} points to a missing file: {override}"
            raise NativeLibraryError(msg)
        return path

    goos, goarch, ext = _platform_tag()
    path = _BUNDLED_DIR / f"{LIBRARY_NAME}-{goos}-{goarch}.{ext}"
    if not path.is_file():
        msg = (
            f"Native Directory library not found at {path}. Build it with "
            "`task wrapperlib:compile` in the agntcy/dir repository and copy the "
            f"result there, or set {LIBRARY_ENV_VAR} to its location."
        )
        raise NativeLibraryError(msg)
    return path


class NativeLibrary:
    """Thin, typed wrapper over the exported libdirwrapper functions."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        try:
            self._lib = ctypes.CDLL(str(self.path))
        except OSError as e:
            msg = f"Failed to load native Directory library {self.path}: {e}"
            raise NativeLibraryError(msg) from e

        # Return raw pointers so the strings can be freed after copying.
        for name, argtypes in (
            ("NewClient", [ctypes.c_char_p]),
            ("CloseClient", [ctypes.c_longlong]),
            ("SignWithKey", [ctypes.c_char_p]),
            ("SignWithOIDC", [ctypes.c_char_p]),
            ("Sign", [ctypes.c_longlong, ctypes.c_char_p]),
            ("VerifyWithKey", [ctypes.c_char_p]),
            ("VerifyWithOIDC", [ctypes.c_char_p]),
            ("Verify", [ctypes.c_longlong, ctypes.c_char_p]),
            ("PullSignatures", [ctypes.c_longlong, ctypes.c_char_p]),
            ("PullPublicKeys", [ctypes.c_longlong, ctypes.c_char_p]),
        ):
            fn = getattr(self._lib, name)
            fn.argtypes = argtypes
            fn.restype = ctypes.c_void_p
        self._lib.FreeCString.argtypes = [ctypes.c_void_p]
        self._lib.FreeCString.restype = None

    def call(self, function: str, *args: dict[str, Any] | str | int) -> dict[str, Any]:
        """Invoke ``function`` and return its decoded JSON response.

        ``dict`` arguments are JSON-encoded, ``str`` arguments are sent as-is (already
        JSON) and ints are passed as client handles.
        Errors reported by the library are raised as :class:`NativeLibraryError`.
        """
        c_args = [
            json.dumps(a).encode("utf-8")
            if isinstance(a, dict)
            else a.encode("utf-8")
            if isinstance(a, str)
            else a
            for a in args
        ]
        ptr = getattr(self._lib, function)(*c_args)
        if not ptr:
            msg = f"Native call {function} returned no data"
            raise NativeLibraryError(msg)
        try:
            raw = ctypes.string_at(ptr)
        finally:
            self._lib.FreeCString(ptr)

        try:
            response = json.loads(raw)
        except json.JSONDecodeError as e:
            msg = f"Native call {function} returned invalid JSON: {e}"
            raise NativeLibraryError(msg) from e
        if response.get("error"):
            raise NativeLibraryError(response["error"])
        return response


_library: NativeLibrary | None = None
_library_lock = threading.Lock()


def load_library() -> NativeLibrary:
    """Load the shared library once per process."""
    global _library
    with _library_lock:
        if _library is None:
            _library = NativeLibrary(find_library_path())
        return _library
