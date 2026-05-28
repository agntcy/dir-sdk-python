# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""High-level facade for AGNTCY Directory client operations."""

from __future__ import annotations

import builtins
import logging
from collections.abc import Sequence

import grpc

from agntcy.dir_sdk.client.auth.session import OAuthSessionManager
from agntcy.dir_sdk.client.config import Config
from agntcy.dir_sdk.client.auth.oauth_pkce import (
    OAuthTokenHolder,
    fetch_openid_configuration,
    run_loopback_pkce_login,
)
from agntcy.dir_sdk.client.services.events import EventService
from agntcy.dir_sdk.client.services.naming import NamingService
from agntcy.dir_sdk.client.services.publication import PublicationService
from agntcy.dir_sdk.client.services.routing import RoutingService
from agntcy.dir_sdk.client.services.search import SearchService
from agntcy.dir_sdk.client.services.signing import SignService
from agntcy.dir_sdk.client.services.store import StoreService
from agntcy.dir_sdk.client.services.sync import SyncService
from agntcy.dir_sdk.client.auth.token_cache import CachedToken, TokenCache
from agntcy.dir_sdk.client.transport.channels import create_grpc_channel
from agntcy.dir_sdk.client.transport.interceptors import (
    BearerAuthInterceptor,
    JWTAuthInterceptor,
)
from agntcy.dir_sdk.models import (
    core_v1,
    events_v1,
    naming_v1,
    routing_v1,
    search_v1,
    sign_v1,
    store_v1,
)

logger = logging.getLogger("client")

__all__ = [
    "BearerAuthInterceptor",
    "CachedToken",
    "Client",
    "JWTAuthInterceptor",
    "OAuthTokenHolder",
    "TokenCache",
    "fetch_openid_configuration",
    "run_loopback_pkce_login",
]


class Client:
    """High-level client for interacting with AGNTCY Directory services."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config.load_from_env()
        self.oauth_session = OAuthSessionManager(self.config)

        channel = create_grpc_channel(
            self.config,
            oauth_holder=self.oauth_session.oauth_holder,
        )

        # Expose raw stubs for advanced callers.
        self.store_client = store_v1.StoreServiceStub(channel)
        self.routing_client = routing_v1.RoutingServiceStub(channel)
        self.publication_client = routing_v1.PublicationServiceStub(channel)
        self.search_client = search_v1.SearchServiceStub(channel)
        self.sign_client = sign_v1.SignServiceStub(channel)
        self.sync_client = store_v1.SyncServiceStub(channel)
        self.event_client = events_v1.EventServiceStub(channel)
        self.naming_client = naming_v1.NamingServiceStub(channel)

        # Service-layer adapters grouped by technical area.
        self.store_service = StoreService(self.store_client, logger)
        self.routing_service = RoutingService(self.routing_client, logger)
        self.publication_service = PublicationService(self.publication_client, logger)
        self.search_service = SearchService(self.search_client, logger)
        self.sign_service = SignService(self.config, self.sign_client, logger)
        self.sync_service = SyncService(self.sync_client, logger)
        self.event_service = EventService(self.event_client, logger)
        self.naming_service = NamingService(self.naming_client, logger)

    def has_cached_oauth_token(self) -> bool:
        return self.oauth_session.has_access_token()

    def get_access_token(self) -> str:
        oauth_holder = self.oauth_session.oauth_holder
        if oauth_holder is None:
            msg = "OAuth token holder not initialized"
            raise RuntimeError(msg)
        return oauth_holder.get_access_token()

    def authenticate_oauth_pkce(self) -> None:
        self.oauth_session.authenticate()
        print("Authenticated with OAuth PKCE")
        print("Access token acquired.")

    def publish(
        self,
        req: routing_v1.PublishRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> None:
        self.routing_service.publish(req, metadata=metadata)

    def list(
        self,
        req: routing_v1.ListRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> list[routing_v1.ListResponse]:
        return self.routing_service.list(req, metadata=metadata)

    def search_cids(
        self,
        req: search_v1.SearchCIDsRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> builtins.list[search_v1.SearchCIDsResponse]:
        return self.search_service.search_cids(req, metadata=metadata)

    def search_records(
        self,
        req: search_v1.SearchRecordsRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> builtins.list[search_v1.SearchRecordsResponse]:
        return self.search_service.search_records(req, metadata=metadata)

    def unpublish(
        self,
        req: routing_v1.UnpublishRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> None:
        self.routing_service.unpublish(req, metadata=metadata)

    def push(
        self,
        records: builtins.list[core_v1.Record],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> builtins.list[core_v1.RecordRef]:
        return self.store_service.push(records, metadata=metadata)

    def push_referrer(
        self,
        req: builtins.list[store_v1.PushReferrerRequest],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> builtins.list[store_v1.PushReferrerResponse]:
        return self.store_service.push_referrer(req, metadata=metadata)

    def pull(
        self,
        refs: builtins.list[core_v1.RecordRef],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> builtins.list[core_v1.Record]:
        return self.store_service.pull(refs, metadata=metadata)

    def pull_referrer(
        self,
        req: builtins.list[store_v1.PullReferrerRequest],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> builtins.list[store_v1.PullReferrerResponse]:
        return self.store_service.pull_referrer(req, metadata=metadata)

    def lookup(
        self,
        refs: builtins.list[core_v1.RecordRef],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> builtins.list[core_v1.RecordMeta]:
        return self.store_service.lookup(refs, metadata=metadata)

    def delete(
        self,
        refs: builtins.list[core_v1.RecordRef],
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> None:
        self.store_service.delete(refs, metadata=metadata)

    def create_sync(
        self,
        req: store_v1.CreateSyncRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> store_v1.CreateSyncResponse:
        return self.sync_service.create_sync(req, metadata=metadata)

    def list_syncs(
        self,
        req: store_v1.ListSyncsRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> builtins.list[store_v1.ListSyncsItem]:
        return self.sync_service.list_syncs(req, metadata=metadata)

    def get_sync(
        self,
        req: store_v1.GetSyncRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> store_v1.GetSyncResponse:
        return self.sync_service.get_sync(req, metadata=metadata)

    def delete_sync(
        self,
        req: store_v1.DeleteSyncRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> None:
        self.sync_service.delete_sync(req, metadata=metadata)

    def listen(
        self,
        req: events_v1.ListenRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> grpc.UnaryStreamMultiCallable:
        return self.event_service.listen(req, metadata=metadata)

    def create_publication(
        self,
        req: routing_v1.PublishRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> routing_v1.CreatePublicationResponse:
        return self.publication_service.create_publication(req, metadata=metadata)

    def get_publication(
        self,
        req: routing_v1.GetPublicationRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> routing_v1.GetPublicationResponse:
        return self.publication_service.get_publication(req, metadata=metadata)

    def list_publication(
        self,
        req: routing_v1.ListPublicationsRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> builtins.list[routing_v1.ListPublicationsItem]:
        return self.publication_service.list_publication(req, metadata=metadata)

    def resolve(
        self,
        name: str,
        version: str | None = None,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> naming_v1.ResolveResponse:
        return self.naming_service.resolve(name, version=version, metadata=metadata)

    def get_verification_info(
        self,
        cid: str | None = None,
        name: str | None = None,
        version: str | None = None,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> naming_v1.GetVerificationInfoResponse:
        return self.naming_service.get_verification_info(
            cid=cid,
            name=name,
            version=version,
            metadata=metadata,
        )

    def verify(
        self,
        req: sign_v1.VerifyRequest,
        metadata: Sequence[tuple[str, str]] | None = None,
    ) -> sign_v1.VerifyResponse:
        return self.sign_service.verify(req, metadata=metadata)

    def sign(self, req: sign_v1.SignRequest) -> None:
        self.sign_service.sign(req)
