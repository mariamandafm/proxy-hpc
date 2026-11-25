import logging
from typing import Literal, Union, Annotated

from pydantic import BaseModel, Field

from coreaai_proxy_plugins.helpers.logging import ExtraLogger


class AttributeNotFoundException(Exception):
    pass


logger = ExtraLogger(logging.getLogger(__name__))


class _AttributePath(BaseModel):
    name: str
    path: list[str] = []


class CustomPath(_AttributePath):
    name: Literal["custom_path"] = "custom_path"
    path: list[str] = []


class UserEmailAddress(_AttributePath):
    name: Literal["user_email_address"] = "user_email_address"
    path: list[str] = [
        "attributes",
        "mail",
    ]


AttributePath = Annotated[
    Union[
        UserEmailAddress,
        CustomPath,
    ],
    Field(..., discriminator="name"),
]


class Attribute(BaseModel):
    attribute_path: AttributePath

    def _traverse_to_node(self, satosa_data, create_parent_paths):
        parent = None
        path = None
        value = satosa_data

        for path in self.attribute_path.path:
            if type(value) is list:
                path = int(path)

            try:
                parent = value
                value = value.__getitem__(path)
            except KeyError:
                logger.warning(
                    f"Attribute not found. path:{self.attribute_path.path}, "
                    f"source: {satosa_data}"
                )
                logger.warning(f"SOURCE TYPE: {type(satosa_data)}")
                if not create_parent_paths:
                    raise AttributeNotFoundException

                # TODO: support for lists?
                value = {}
                parent[path] = value
            except TypeError:
                logger.warning(
                    f"Attribute not found. path:{self.attribute_path.path}, "
                    f"source: {satosa_data}"
                )
                if not create_parent_paths:
                    raise AttributeNotFoundException

                # TODO: support for lists?
                value = {}
                parent[path] = value

        return parent, path, value

    def extract_value(self, data):
        _, _, value = self._traverse_to_node(data, False)

        logger.debug(
            f"Attribute found. path:{self.attribute_path.path}, "
            f"source: {data}, value: {value}"
        )
        return value

    def set_value(
        self,
        satosa_data,
        new_value,
        create_parent_paths=True,
        override_existing_value=False,
    ):
        parent, key, value = self._traverse_to_node(satosa_data, create_parent_paths)

        if (not value) or override_existing_value:
            parent[key] = new_value
