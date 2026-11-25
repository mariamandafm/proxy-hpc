import json
import logging
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, HttpUrl, SecretStr, Field
from pydantic.env_settings import BaseSettings
from satosa.context import Context
from satosa.internal import InternalData
from typing_extensions import Self

from coreaai_proxy_plugins.satosa.micro_services.session_store_req import (
    post_session_payload_to_api,
    get_session_payload_from_api,
)

_logger = logging.getLogger(__name__)


class ResumableContext(BaseModel):
    target_micro_service: Optional[str] = None
    target_backend: Optional[str] = None
    target_frontend: Optional[str] = None
    internal_data: dict[str, Any]
    state: dict[str, Any]

    @property
    def session_id(self) -> str:
        return self.state["SESSION_ID"]

    def resume_context(self, ctx: Context) -> Context:
        ctx.target_frontend = self.target_frontend
        ctx.target_backend = self.target_backend
        ctx.target_micro_service = self.target_micro_service
        ctx.internal_data |= self.internal_data
        ctx.state.data |= self.state
        return ctx

    @classmethod
    def from_context(cls, context: Context) -> Self:
        try:
            # MetadataStore is a huge unpicklable pile of values
            internal_data = deepcopy(
                context.internal_data | {Context.KEY_METADATA_STORE: None}
            )
            state = deepcopy(context.state)
        except Exception as e:
            _logger.error(f"Failed to deepcopy context: {e}", exc_info=e)
            raise e
        return cls(
            target_micro_service=context.target_micro_service,
            target_backend=context.target_backend,
            target_frontend=context.target_frontend,
            internal_data=internal_data,
            state=state,
        )


class SessionData(BaseModel):
    internal_data: dict[str, Any]
    context_data: ResumableContext


class ResumeState(BaseModel):
    session_id: str = Field(alias="SESSION_ID")
    created_at: datetime
    resume_id: str
    memorized_idp: Optional[str] = None


class SessionStoreConfig(BaseSettings):
    session_api_url: HttpUrl
    session_api_key: SecretStr
    request_timeout_seconds: int = 5

    def store_session(self, ctx: Context, internal_data: InternalData):
        rctx = ResumableContext.from_context(ctx)
        session_data = SessionData(
            internal_data=internal_data.to_dict(),
            context_data=rctx,
        )
        memorized_idp = rctx.state.get(Context.KEY_MEMORIZED_IDP, None)
        session_id = rctx.session_id
        resume_id = post_session_payload_to_api(
            session_data=session_data.json(exclude_none=True),
            api_base_url=str(self.session_api_url),
            api_key=self.session_api_key.get_secret_value(),
            api_timeout=self.request_timeout_seconds,
        )
        resume_state = ResumeState(
            created_at=datetime.now(timezone.utc),
            resume_id=resume_id,
            SESSION_ID=session_id,
            memorized_idp=memorized_idp,
        )
        resume_state_json = resume_state.json(exclude_none=True, by_alias=True)
        resume_state_dict = json.loads(resume_state_json)
        ctx.state.clear()
        ctx.state.update(resume_state_dict)

    def resume_session(self, ctx: Context) -> tuple[Context, InternalData]:
        resume_state = ResumeState.parse_obj(ctx.state.data)
        session_data_json, _ = get_session_payload_from_api(
            api_base_url=str(self.session_api_url),
            session_id=resume_state.resume_id,
            api_key=self.session_api_key.get_secret_value(),
            api_timeout=self.request_timeout_seconds,
        )
        session_data = SessionData.parse_raw(session_data_json)
        _ = ctx.state.pop("resume_id", None)
        ctx = session_data.context_data.resume_context(ctx)
        internal_data = InternalData.from_dict(session_data.internal_data)
        return ctx, internal_data


