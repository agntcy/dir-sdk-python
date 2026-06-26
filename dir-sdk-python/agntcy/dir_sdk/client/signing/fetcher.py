# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Store-backed fetcher for signature verification."""

from __future__ import annotations

from agntcy.dir_sdk.client.services.store import StoreService
from agntcy.dir_sdk.client.signing.referrers import (
    unmarshal_public_key_referrer,
    unmarshal_signature_referrer,
)
from agntcy.dir_sdk.models import core_v1, sign_v1, store_v1


class StoreFetcher:
    def __init__(self, store_service: StoreService) -> None:
        self._store_service = store_service

    def lookup(self, record_ref: core_v1.RecordRef) -> None:
        results = self._store_service.lookup([record_ref])
        if not results:
            msg = "record not found"
            raise LookupError(msg)

    def pull_signatures(self, record_ref: core_v1.RecordRef) -> list[sign_v1.Signature]:
        responses = self._store_service.pull_referrer(
            [
                store_v1.PullReferrerRequest(
                    record_ref=record_ref,
                    referrer_type=sign_v1.Signature.DESCRIPTOR.full_name,
                )
            ]
        )
        signatures: list[sign_v1.Signature] = []
        for response in responses:
            if response.referrer is None:
                continue
            try:
                signatures.append(unmarshal_signature_referrer(response.referrer))
            except ValueError:
                continue
        return signatures

    def pull_public_keys(self, record_ref: core_v1.RecordRef) -> list[str]:
        responses = self._store_service.pull_referrer(
            [
                store_v1.PullReferrerRequest(
                    record_ref=record_ref,
                    referrer_type=sign_v1.PublicKey.DESCRIPTOR.full_name,
                )
            ]
        )
        public_keys: list[str] = []
        for response in responses:
            if response.referrer is None:
                continue
            try:
                public_key = unmarshal_public_key_referrer(response.referrer)
            except ValueError:
                continue
            if public_key.key:
                public_keys.append(public_key.key)
        return public_keys
