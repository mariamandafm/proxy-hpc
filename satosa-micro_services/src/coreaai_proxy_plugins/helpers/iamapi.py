from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta
from enum import Enum
from typing import Literal, Optional, Mapping, Any, TypeVar, Type, Union
from urllib.parse import urlencode, urljoin

from pydantic import AnyHttpUrl, root_validator, BaseModel, Field, ValidationError
from requests import Session, JSONDecodeError, Response, HTTPError
from typing_extensions import Self


class IamApiConfig(BaseModel):
    base_url: AnyHttpUrl
    lookup_endpoint: str = "/api/v0/lookup"
    upsert_identity_endpoint: str = "/api/v0/identity"
    register_user_endpoint: str = "/api/v0/account"
    patch_profile_endpoint: str = "/api/v0/profile"
    mfa_verifications_endpoint: str = "/api/v0/mfa/verifications"
    authorization: Optional[str] = None


PolicyType = Literal["terms_of_use", "privacy_policy", "acceptable_usage_policy"]


class AcceptedPolicy(BaseModel):
    policy_url: AnyHttpUrl
    policy_type: PolicyType


class AccountProfile(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None


class IamApiRole(Enum):
    IAM_ACCOUNT_OWNER = "iam_account_owner"
    IAM_PROXY_SERVICE = "iam_proxy_service"

    @classmethod
    def from_role(cls, value: str) -> Self:
        for member in cls:
            if member.value == value:
                return member
        raise ValueError(f"Invalid {cls.__name__} value: {value}")

    def claims(self, account_uid: Optional[str] = None):
        if account_uid:
            return {
                "iam_role": self.value,
                "iam_account_uid": account_uid,
            }
        else:
            return {
                "iam_role": self.value,
            }


class RegisterAccountParams(BaseModel):
    account_uid: Optional[str] = None
    cuids: list[str] = Field(min_items=1)
    profile: AccountProfile = AccountProfile()
    accepted_policies: list[AcceptedPolicy] = Field(min_items=1)


class LookupParams(BaseModel):
    iuids: list[str] = Field(min_items=1)
    service_uid: str
    issuer_uid: str


class Identity(BaseModel):
    cuid: str

    issuer_uid: str
    account_uid: Optional[str] = None
    iuids: list[str]
    claims: Optional[Mapping[str, Any]] = None
    created_at: datetime
    updated_at: datetime


class LookupIdentity(Identity):
    matches: Optional[list[str]] = None


class Account(BaseModel):
    account_uid: str
    cuids: list[str] = Field(min_items=1)
    accepted_policies: Optional[list[AcceptedPolicy]] = None
    profile: AccountProfile = AccountProfile()
    created_at: datetime
    updated_at: datetime

    @property
    def jwt_claims(self):
        return IamApiRole.IAM_ACCOUNT_OWNER.claims(account_uid=self.account_uid)


class Consent(BaseModel):
    pass


class MFAFactor(BaseModel):
    pass


class MFAVerification(BaseModel):
    verification_id: str
    factor_id: str
    factor_kind: str
    account_uid: str
    attachment: Optional[str] = None
    verified_at: datetime


class LookupResult(BaseModel):
    unresolved: Optional[list[str]] = None
    accounts: Optional[list[Account]] = None
    identities: Optional[list[LookupIdentity]] = None
    consent: Optional[list[Consent]] = None

    @root_validator
    def check_not_empty(cls, values):
        identities = values.get("identities")
        unresolved = values.get("unresolved")
        if not (identities or unresolved):
            raise ValueError("should resolve identities or have unresolved iuids")
        return values

    @property
    def primary_account(self):
        [primary_account, *_] = self.accounts or [None]
        return primary_account


class UpsertIdentityParams(BaseModel):
    cuid: str
    issuer_uid: str
    iuids: list[str]
    claims: dict[str, Any] = Field(default_factory=dict)


class IamApiClient(object):
    _session: Session
    _config: IamApiConfig

    def __init__(self, config: IamApiConfig, session: Optional[Session] = None):
        if session is None:
            session = Session()
        session.headers.update({"Content-Type": "application/json"})
        if config.authorization:
            session.headers.update({"Authorization": config.authorization})
        self._session = session
        self._config = config

    @property
    def config(self):
        return self._config

    @property
    def session(self):
        return self._session

    def _build_url(self, endpoint: str):
        base_url = f"{self.config.base_url}".rstrip("/")
        base_url = f"{base_url}/"
        return urljoin(base_url, endpoint.lstrip("/"))

    def upsert_identity(
        self, params: UpsertIdentityParams, timeout: Optional[float] = None
    ) -> Identity:
        url = self._build_url(self.config.upsert_identity_endpoint)
        response = self._session.request(
            "PUT", url, json=params.dict(), timeout=timeout
        )
        result = parse_api_response(Identity, response)
        return result

    def lookup(
        self, params: LookupParams, timeout: Optional[float] = None
    ) -> LookupResult:
        params = urlencode(params.dict(), doseq=True)
        url = self._build_url(self.config.lookup_endpoint)
        response = self.session.request("GET", url, params=params, timeout=timeout)
        return parse_api_response(LookupResult, response)

    def register_account(
        self, params: RegisterAccountParams, timeout: Optional[float] = None
    ) -> Account:
        url = self._build_url(self.config.register_user_endpoint)
        response = self._session.request(
            "POST", url, json=params.dict(), timeout=timeout
        )
        return parse_api_response(Account, response)

    def patch_account_profile(
        self, account_uid: str, profile: AccountProfile, timeout: Optional[float] = None
    ) -> Account:
        url = self._build_url(self.config.patch_profile_endpoint)
        # Prepare payload with only the profile data
        payload = {"profile": profile.dict(exclude_unset=True)}
        response = self._session.request("PATCH", url, json=payload, timeout=timeout)
        return parse_api_response(Account, response)

    def get_account_mfa_verifications(
        self,
        max_age: timedelta,
        verification_id: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> list[MFAVerification]:
        url = self._build_url(f"{self.config.mfa_verifications_endpoint}")

        params = dict[str, Union[float,str]](max_age_seconds=max_age.total_seconds())
        if verification_id is not None:
            params["verification_id"] = verification_id

        response = self._session.request(
            "GET",
            url,
            params=params,
            timeout=timeout,
        )
        return parse_api_list_response(MFAVerification, response)


T = TypeVar("T", bound=BaseModel)


def parse_api_response(result_model: Type[T], response: Response) -> T:
    _raise_for_status(response)
    try:
        body = response.json()
    except JSONDecodeError as json_error:
        raise InvalidAPIResponse("Response body is not valid JSON") from json_error

    class ResponseBody(BaseModel):
        result: dict[str, Any]

    try:
        result = ResponseBody.parse_obj(body).result
        return result_model.parse_obj(result)
    except ValidationError as validation_error:
        raise InvalidAPIResponse(
            f"Response body is not valid {result_model.__name__}"
        ) from validation_error


def parse_api_list_response(result_model: Type[T], response: Response) -> list[T]:
    _raise_for_status(response)
    try:
        body = response.json()
    except JSONDecodeError as json_error:
        raise InvalidAPIResponse("Response body is not valid JSON") from json_error

    class ResponseBody(BaseModel):
        results: list

    try:
        results = ResponseBody.parse_obj(body).results
        return [result_model.parse_obj(result) for result in results]
    except ValidationError as validation_error:
        raise InvalidAPIResponse(
            f"Response body is not valid {result_model.__name__}"
        ) from validation_error


class APIErrorResponse(Exception):
    pass


class InvalidAPIResponse(Exception):
    pass


def _raise_for_status(response: Response):
    class APIError(BaseModel):
        message: str

    class ErrorResponseBody(BaseModel):
        error: APIError

    try:
        response.raise_for_status()
    except HTTPError as http_error:
        try:
            body = response.json()
        except JSONDecodeError:
            raise InvalidAPIResponse("Response body is not valid JSON") from http_error
        try:
            api_error = ErrorResponseBody.parse_obj(body).error
        except ValidationError:
            raise InvalidAPIResponse("Response body is not valid JSON") from http_error
        raise APIErrorResponse(api_error.message) from http_error


class ResumeState(BaseModel):
    requester: str
    issuer: str
    session_id: str
    created_at: datetime


class SessionData(BaseModel):
    internal_data: dict[str, Any]


class IamApiContext(BaseModel):
    class Config:
        arbitrary_types_allowed = True

    account_owner_api_client: Optional[IamApiClient] = None
    account_info: Optional[LookupResult] = None
    resume_endpoint: str


_context = ContextVar[Optional[IamApiContext]]("IamApiContext", default=None)


@contextmanager
def use_context(ctx: IamApiContext):
    token = _context.set(ctx)
    try:
        yield
    finally:
        _context.reset(token)


def current_context():
    return _context.get()
