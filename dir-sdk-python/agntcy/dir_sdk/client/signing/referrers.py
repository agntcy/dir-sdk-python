# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Marshal and unmarshal signature referrers for the Directory store."""

from __future__ import annotations

import json

from agntcy.dir_sdk.models import core_v1, sign_v1
from google.protobuf import json_format, struct_pb2


def _dict_to_struct(data: dict[str, object]) -> struct_pb2.Struct:
    struct = struct_pb2.Struct()
    json_format.ParseDict(data, struct)
    return struct


def _struct_to_dict(struct: struct_pb2.Struct) -> dict[str, object]:
    return json_format.MessageToDict(struct)


def marshal_signature_referrer(signature: sign_v1.Signature) -> core_v1.RecordReferrer:
    data = json.loads(json_format.MessageToJson(signature))
    return core_v1.RecordReferrer(
        type=sign_v1.Signature.DESCRIPTOR.full_name,
        data=_dict_to_struct(data),
    )


def marshal_public_key_referrer(
    public_key: sign_v1.PublicKey,
) -> core_v1.RecordReferrer:
    data = json.loads(json_format.MessageToJson(public_key))
    return core_v1.RecordReferrer(
        type=sign_v1.PublicKey.DESCRIPTOR.full_name,
        data=_dict_to_struct(data),
    )


def unmarshal_signature_referrer(referrer: core_v1.RecordReferrer) -> sign_v1.Signature:
    if referrer.data is None:
        msg = "referrer data is nil"
        raise ValueError(msg)
    signature = sign_v1.Signature()
    json_format.ParseDict(_struct_to_dict(referrer.data), signature)
    return signature


def unmarshal_public_key_referrer(
    referrer: core_v1.RecordReferrer,
) -> sign_v1.PublicKey:
    if referrer.data is None:
        msg = "referrer data is nil"
        raise ValueError(msg)
    public_key = sign_v1.PublicKey()
    json_format.ParseDict(_struct_to_dict(referrer.data), public_key)
    return public_key
