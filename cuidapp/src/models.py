from typing import List, Optional

from pydantic import BaseModel, RootModel, field_validator


class Entity(BaseModel):
    entity_id: str


class InternalUserIdentifiers(RootModel):
    root: List[str]

    def __iter__(self):
        return iter(self.root)

    def __getitem__(self, item):
        return self.root[item]

    @field_validator("root")
    def root_must_not_be_an_empty_list(cls, v):
        if not v:
            raise ValueError("must not be an empty list")
        return v

    @field_validator("root")
    def root_must_not_have_empty_items(cls, v):
        if not all(v):
            raise ValueError("must not have empty items")
        return v


class CommunityUserIdentifier(BaseModel):
    cuid: str


class RegisterCuidRequest(BaseModel):
    cuid: str
    iuids: InternalUserIdentifiers


class RegisterCuidResponse(RegisterCuidRequest):
    success: bool
    message: Optional[str] = None


class BatchRegisterCuidRequest(BaseModel):
    records: list[RegisterCuidRequest]


class BatchRegisterCuidResponse(BaseModel):
    results: list[RegisterCuidResponse]


class MigrateCuidRequest(BaseModel):
    source_cuid: str
    target_cuid: str
