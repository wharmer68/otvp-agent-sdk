"""Supabase Management API client for verification agents.

Uses stdlib ``urllib`` only — no extra dependencies.  Requires a personal
access token from https://supabase.com/dashboard/account/tokens.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.request
import urllib.error
from typing import Any

logger = logging.getLogger("otvp.agent.supabase.management")

DEFAULT_API_URL = "https://api.supabase.com"


class ManagementAPIError(Exception):
    """Raised when a Management API call fails."""


class SupabaseManagementAPI:
    """Lightweight client for the Supabase Management API.

    Reads configuration from environment variables by default::

        api = SupabaseManagementAPI()
        auth_config = api.get_auth_config()
    """

    def __init__(
        self,
        access_token: str | None = None,
        project_ref: str | None = None,
        api_url: str | None = None,
    ) -> None:
        self.access_token = access_token or os.environ.get("SUPABASE_ACCESS_TOKEN", "")
        self.project_ref = project_ref or os.environ.get("SUPABASE_PROJECT_REF", "")
        self.api_url = (api_url or os.environ.get("SUPABASE_API_URL", DEFAULT_API_URL)).rstrip("/")

    def _request(self, path: str) -> dict[str, Any] | list[Any]:
        """Make an authenticated GET request to the Management API."""
        if not self.access_token:
            raise ManagementAPIError(
                "SUPABASE_ACCESS_TOKEN is not set. "
                "Create one at https://supabase.com/dashboard/account/tokens"
            )
        if not self.project_ref:
            raise ManagementAPIError(
                "SUPABASE_PROJECT_REF is not set. "
                "Provide it via environment variable or constructor parameter."
            )

        url = f"{self.api_url}{path}"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json",
                "User-Agent": "otvp-agent-sdk/1.0.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body)
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8")
            except Exception:
                pass
            raise ManagementAPIError(
                f"Management API returned {exc.code} for {url}: {body}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ManagementAPIError(
                f"Failed to reach Management API at {url}: {exc.reason}"
            ) from exc

    def get_auth_config(self) -> dict[str, Any]:
        """Fetch auth configuration for the project.

        Endpoint: GET /v1/projects/{ref}/config/auth
        """
        return self._request(f"/v1/projects/{self.project_ref}/config/auth")

    def get_project_settings(self) -> dict[str, Any]:
        """Fetch project-level settings.

        Endpoint: GET /v1/projects/{ref}
        """
        result = self._request(f"/v1/projects/{self.project_ref}")
        return result if isinstance(result, dict) else {}

    def get_api_keys(self) -> list[dict[str, Any]]:
        """Fetch API keys for the project.

        Endpoint: GET /v1/projects/{ref}/api-keys
        """
        result = self._request(f"/v1/projects/{self.project_ref}/api-keys")
        return result if isinstance(result, list) else []
