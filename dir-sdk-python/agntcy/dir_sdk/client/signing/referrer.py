# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Referrer encoding for signatures and public keys.

Mirrors ``MarshalReferrer``/``UnmarshalReferrer`` from the Go
``api/sign/v1`` package: the message is encoded with protojson (camelCase
field names, default values omitted) into a ``google.protobuf.Struct`` and the
referrer ``type`` is the protobuf full name of the message.
"""

from __future__ import annotations

from agntcy.dir_sdk.models import core_v1, sign_v1
from google.protobuf import json_format, struct_pb2

SIGNATURE_REFERRER_TYPE = sign_v1.Signature.DESCRIPTOR.full_name
PUBLIC_KEY_REFERRER_TYPE = sign_v1.PublicKey.DESCRIPTOR.full_name


def _marshal(message: sign_v1.Signature | sign_v1.PublicKey) -> struct_pb2.Struct:
    data = struct_pb2.Struct()
    json_format.ParseDict(json_format.MessageToDict(message), data)
    return data


def _unmarshal(
    referrer: core_v1.RecordReferrer,
    message: sign_v1.Signature | sign_v1.PublicKey,
) -> None:
    if referrer is None or not referrer.HasField("data"):
        msg = "referrer or data is nil"
        raise ValueError(msg)
    json_format.ParseDict(json_format.MessageToDict(referrer.data), message)


def marshal_signature(signature: sign_v1.Signature) -> core_v1.RecordReferrer:
    """Export a Signature into a RecordReferrer."""
    return core_v1.RecordReferrer(
        type=SIGNATURE_REFERRER_TYPE,
        data=_marshal(signature),
    )


def unmarshal_signature(referrer: core_v1.RecordReferrer) -> sign_v1.Signature:
    """Load a Signature from a RecordReferrer."""
    signature = sign_v1.Signature()
    _unmarshal(referrer, signature)
    return signature


def marshal_public_key(public_key: sign_v1.PublicKey) -> core_v1.RecordReferrer:
    """Export a PublicKey into a RecordReferrer."""
    return core_v1.RecordReferrer(
        type=PUBLIC_KEY_REFERRER_TYPE,
        data=_marshal(public_key),
    )


def unmarshal_public_key(referrer: core_v1.RecordReferrer) -> sign_v1.PublicKey:
    """Load a PublicKey from a RecordReferrer."""
    public_key = sign_v1.PublicKey()
    _unmarshal(referrer, public_key)
    return public_key
