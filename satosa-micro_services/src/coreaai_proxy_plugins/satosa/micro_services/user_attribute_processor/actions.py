from typing import Literal, Any, Annotated, Union

from pydantic import BaseModel, AnyHttpUrl, Field
from satosa.internal import InternalData
from satosa.response import Redirect as satosa_redirect

from .attributes import Attribute


class ActionException(Exception):
    pass


class BaseAction(BaseModel):
    name: str
    is_terminal: bool = False

    def process(self, internal_data: InternalData):
        raise NotImplementedError


class Redirect(BaseAction):
    name: Literal["redirect"] = "redirect"
    redirect_url: AnyHttpUrl
    is_terminal = True

    def process(self, internal_data: InternalData):
        return satosa_redirect(self.redirect_url)


class NextMicroservice(BaseAction):
    name: Literal["next_microservice"] = "next_microservice"
    is_terminal = True

    def process(self, internal_data: InternalData):
        return None


class AddLiteralAttribute(BaseAction):
    name: Literal["add_literal_attribute"] = "add_literal_attribute"
    attribute: Attribute
    value: Any
    is_terminal = False
    create_parent_paths: bool = True
    override_existing_value: bool = True

    def process(self, internal_data: InternalData):
        self.attribute.set_value(
            internal_data,
            self.value,
            create_parent_paths=self.create_parent_paths,
            override_existing_value=self.override_existing_value,
        )


Action = Annotated[
    Union[
        Redirect,
        AddLiteralAttribute,
        NextMicroservice,
    ],
    Field(..., discriminator="name"),
]
