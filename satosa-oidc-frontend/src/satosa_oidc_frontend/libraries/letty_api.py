import logging
from http import HTTPStatus
from typing import Iterable, Optional
from urllib.parse import parse_qs, urlsplit

import requests
from cachetools.func import ttl_cache
from satosa_oidc_frontend.types import ClientId, ClientInfo, ClientSource, Undefined
from satosa_oidc_frontend.utils import secured_ttl_cache

logger = logging.getLogger(__name__)

api_session = requests.Session()

TIMEOUT_SECONDS = 3


class LettyException(Exception):
    pass


class UnsupportedLettyOperation(LettyException):
    pass


class LettySecretVerifier:
    @staticmethod
    @secured_ttl_cache(ttl=5)
    def _verify_secret_cached(
        api_url: str, client_id: ClientId, client_secret: str
    ) -> bool:
        response = api_session.post(
            f"{api_url}/services/oidc/verify",
            json={
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=TIMEOUT_SECONDS,
        )

        if response.status_code == HTTPStatus.NO_CONTENT:
            return True

        if response.status_code != HTTPStatus.UNAUTHORIZED:
            logger.error("Unexpected error when verifying client secret from Letty")

        return False

    def __init__(self, api_url: str, client_id: ClientId) -> None:
        self.api_url = api_url
        self.client_id = client_id

    def __eq__(self, __value: object) -> bool:
        return LettySecretVerifier._verify_secret_cached(
            self.api_url, self.client_id, __value
        )

    def __hash__(self) -> int:
        return hash((self.api_url, self.client_id))


# This is a hack to expose `__contains__`` when idpy-oidc calls `in x.keys()`
class _LettyClientIdSet(Iterable):
    def __init__(self, api_url: str):
        self.api_url = api_url

    def __contains__(self, client_id: ClientId) -> bool:  # type:  ignore
        return (
            LettyClientsAPI._get_and_cache_info_by_client_id(self.api_url, client_id)
            is not None
        )

    def __iter__(self):
        return self

    def __next__(self):
        logger.debug("List of client IDs not retrieved")
        raise StopIteration


class LettyClientsAPI(ClientSource):
    @staticmethod
    def _parse_client_info(api_url: str, client_info_raw: dict) -> ClientInfo:
        client_metadata = client_info_raw.get("metadata", {})

        client_info = {
            "client_id": client_metadata["id"],
            "client_secret": LettySecretVerifier(
                api_url, ClientId(client_metadata["id"])
            ),
            "client_name": client_info_raw.get("service_name", ""),
            "client_uri": client_info_raw.get("service_website", ""),
            "organization_name": client_info_raw.get("organization_name", Undefined),
            "organization_website": client_info_raw.get(
                "organization_website", Undefined
            ),
            "service_description": client_info_raw.get(
                "service_description", Undefined
            ),
            "policy_uri": client_info_raw.get("privacy_policy_url", Undefined),
            "tos_uri": client_info_raw.get("terms_of_use_url", Undefined),
            "grant_types_supported": client_metadata.get("oidc_grants", Undefined),
            "allowed_scopes": client_metadata.get("oidc_scopes", Undefined),
            # TODO: Not in Letty -- need to further discuss how to get/use this
            "add_claims": {
                "always": {
                    "introspection": [
                        "entitlements",
                        "eduperson_entitlement",
                        "given_name",
                        "family_name",
                        "email",
                    ]
                },
                "by_scope": {
                    "introspection": True,
                },
            },
            "response_types_supported": [
                (" ").join(resp_types)
                for resp_types in client_metadata.get("oidc_response_types", [])
            ]
            or Undefined,
            "token_endpoint_client_authn_method": client_metadata.get(
                "oidc_authn_methods",
                Undefined,
            ),
            "introspection_endpoint_client_authn_method": client_metadata.get(
                "oidc_authn_methods",
                Undefined,
            ),
            "pkce_essential": bool(client_metadata.get("oidc_pkce")) or Undefined,
            "redirect_uris": [
                [redirect_uri.split("?")[0], parse_qs(urlsplit(redirect_uri).query)]
                for redirect_uri in client_metadata.get("oidc_redirect_uris", [])
            ],
            "application_type": client_metadata.get("oidc_application_type", Undefined),
            "revoke_refresh_on_issue": client_metadata.get(
                "oidc_revoke_refresh_on_issue", Undefined
            ),
        }

        token_usage_rules = {
            "id_token": client_metadata.get("oidc_id_token_usage_rules", Undefined),
            "access_token": client_metadata.get(
                "oidc_access_token_usage_rules", Undefined
            ),
            "refresh_token": client_metadata.get(
                "oidc_refresh_token_usage_rules", Undefined
            ),
            "code": client_metadata.get("oidc_authz_code_usage_rules", Undefined),
        }
        client_info["token_usage_rules"] = {
            k: v for k, v in token_usage_rules.items() if v is not Undefined
        } or Undefined

        # Remove undefined values
        client_info = {k: v for k, v in client_info.items() if v is not Undefined}

        return ClientInfo(client_info)

    @staticmethod
    @ttl_cache(ttl=15)
    def _get_and_cache_info_by_client_id(
        api_url: str, client_id: ClientId
    ) -> Optional[ClientInfo]:
        response = api_session.get(
            f"{api_url}/services/oidc/{client_id}",
            timeout=TIMEOUT_SECONDS,
        )
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None
        if response.status_code != HTTPStatus.OK:
            logger.error("Unexpected error when retrieving client from Letty")
            return None

        try:
            client_info_raw = response.json()
            return LettyClientsAPI._parse_client_info(api_url, client_info_raw)
        except Exception as e:
            logger.error("Error parsing client info")
            logger.debug(e)
            raise

    def __init__(self, api_url: str):
        self.api_url = api_url

    def _get_info_by_client_id(self, client_id: ClientId) -> Optional[ClientInfo]:
        return LettyClientsAPI._get_and_cache_info_by_client_id(self.api_url, client_id)

    def __contains__(self, client_id: ClientId) -> bool:  # type:  ignore
        return self._get_info_by_client_id(client_id) is not None

    def __getitem__(self, client_id: ClientId) -> ClientInfo:
        client_info = self._get_info_by_client_id(client_id)
        if not client_info:
            raise KeyError
        return client_info

    def __setitem__(self, __client_id: ClientId, __client_info: ClientInfo) -> None:
        raise UnsupportedLettyOperation("Adding/updating clients is not supported")

    def get(  # type: ignore
        self,
        client_id: ClientId,
        default: Optional[ClientInfo] = None,
    ) -> ClientInfo:
        return self._get_info_by_client_id(client_id) or default or ClientInfo({})

    def set(self, __client_id: ClientId, __client_info: ClientInfo) -> None:
        raise UnsupportedLettyOperation("Adding/updating clients is not supported")

    def update(self, __clients: dict[ClientId, ClientInfo]) -> None:  # type: ignore
        raise UnsupportedLettyOperation("Adding/updating clients is not supported")

    def keys(self) -> Iterable[ClientId]:  # type: ignore
        return _LettyClientIdSet(self.api_url)
