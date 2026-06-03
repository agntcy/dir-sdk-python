# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""OAuth session management and token cache integration."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from agntcy.dir_sdk.client.config import Config
from agntcy.dir_sdk.client.auth.oauth_pkce import (
    OAuthTokenHolder,
    fetch_openid_configuration,
    run_loopback_pkce_login,
)
from agntcy.dir_sdk.client.auth.token_cache import CachedToken, TokenCache


def cached_token_from_response(
    config: Config, payload: dict[str, object]
) -> CachedToken:
    expires_at = None
    expires_in = payload.get("expires_in")
    if expires_in is not None:
        expires_at = datetime.now(UTC) + timedelta(seconds=int(expires_in))

    refresh_token = payload.get("refresh_token")
    token_type = payload.get("token_type")
    return CachedToken(
        access_token=str(payload["access_token"]),
        token_type=str(token_type) if isinstance(token_type, str) else "",
        provider="oidc",
        issuer=config.oidc_issuer,
        refresh_token=str(refresh_token) if isinstance(refresh_token, str) else "",
        expires_at=expires_at,
        created_at=datetime.now(UTC),
    )


class OAuthSessionManager:
    """Coordinates OIDC token state with interactive PKCE flow and cache."""

    def __init__(
        self,
        config: Config,
        token_cache: TokenCache | None = None,
    ) -> None:
        self.config = config
        self._token_cache = token_cache or TokenCache()
        self._oauth_holder: OAuthTokenHolder | None = None

        if self.config.auth_mode == "oidc":
            self._oauth_holder = OAuthTokenHolder()
            if self.config.auth_token:
                self._oauth_holder.set_tokens(self.config.auth_token)
            else:
                cached_token = self._token_cache.get_valid_token()
                if cached_token is not None:
                    self._oauth_holder.set_tokens(cached_token.access_token)

    @property
    def oauth_holder(self) -> OAuthTokenHolder | None:
        return self._oauth_holder

    def has_access_token(self) -> bool:
        if self._oauth_holder is None:
            return False
        try:
            self._oauth_holder.get_access_token()
            return True
        except RuntimeError:
            return False

    def authenticate(self) -> None:
        if self.config.auth_mode != "oidc":
            msg = "authenticate_oauth_pkce() requires auth_mode='oidc'"
            raise ValueError(msg)
        if not self.config.oidc_issuer:
            msg = "oidc_issuer is required for authenticate_oauth_pkce()"
            raise ValueError(msg)
        if not self.config.oidc_client_id:
            msg = "oidc_client_id is required for authenticate_oauth_pkce()"
            raise ValueError(msg)
        if self._oauth_holder is None:
            msg = "OAuth token holder not initialized"
            raise RuntimeError(msg)

        meta = fetch_openid_configuration(
            self.config.oidc_issuer,
            verify=not self.config.tls_skip_verify,
            timeout=min(30.0, self.config.oidc_auth_timeout),
        )
        payload = run_loopback_pkce_login(self.config, metadata=meta)
        self._oauth_holder.update_from_token_response(payload)
        self._token_cache.save(cached_token_from_response(self.config, payload))
