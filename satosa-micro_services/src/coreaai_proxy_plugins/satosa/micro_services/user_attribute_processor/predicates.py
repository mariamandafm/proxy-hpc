from enum import Enum
from typing import Literal, Annotated, Union

from pydantic import BaseModel, Field, validator
from satosa.internal import InternalData

from .attributes import Attribute


class PredicateException(Exception):
    pass


class MatchModeEnum(str, Enum):
    ANY = "any"
    FIRST = "first"
    LAST = "last"


class BaseCondition(BaseModel):
    name: str

    def check(self, internal_data: InternalData) -> bool:
        raise NotImplementedError


class IsContainedInStaticList(BaseCondition):
    name: Literal["is_contained_in_static_list"] = "is_contained_in_static_list"
    source_attribute: Attribute
    static_list: list
    ignore_case: bool = False
    match_mode: MatchModeEnum = MatchModeEnum.ANY

    def check(self, internal_data: InternalData) -> bool:
        value = self.source_attribute.extract_value(internal_data)

        if not value:
            return False

        temp_static_list = self.static_list
        if self.ignore_case:
            temp_static_list = [s.lower() for s in self.static_list]

        if type(value) is list:
            if self.ignore_case:
                value = [s.lower() for s in value]

            if self.match_mode == MatchModeEnum.ANY:
                return bool(set(value) & set(temp_static_list))
            else:
                index = 0 if self.match_mode == MatchModeEnum.FIRST else -1
                value = value[index]

        if self.ignore_case:
            value = value.lower()

        return value in temp_static_list


class RegexMatch(BaseCondition):
    name: Literal["regex_match"] = "regex_match"
    ignore_case: bool = False
    source_attribute: Attribute
    regex_pattern: str

    def check(self, internal_data: InternalData) -> bool:
        import re

        source = self.source_attribute.extract_value(internal_data)

        re_flags = 0

        if self.ignore_case:
            # This is represented by bitwise checking, so we add all the flags
            # to not lose other flags in the future
            re_flags += re.IGNORECASE

        return bool(re.match(self.regex_pattern, source, flags=re_flags))


class NotOperator(BaseCondition):
    name: Literal["not"] = "not"
    condition: "Condition"

    def check(self, internal_data: InternalData) -> bool:
        return not self.condition.check(internal_data)


class BaseComposition(BaseCondition):
    conditions: list["Condition"]

    @validator("conditions")
    def check_minimum_length(cls, v):
        if len(v) < 1:
            raise PredicateException("Condition list must contain at least 1 item")
        return v

    def reduce(self, left_result, right_result) -> bool:
        raise NotImplementedError

    def check(self, internal_data: InternalData) -> bool:
        current = self.conditions[0].check(internal_data)

        for cond in self.conditions[1:]:
            current = self.reduce(current, cond.check(internal_data))

        return current


class OrComposition(BaseComposition):
    name: Literal["or"] = "or"

    def reduce(self, left_result, right_result) -> bool:
        return left_result or right_result


class AndComposition(BaseComposition):
    name: Literal["and"] = "and"

    def reduce(self, left_result, right_result) -> bool:
        return left_result and right_result


class AlwaysTrue(BaseCondition):
    name: Literal["always_true"] = "always_true"

    def check(self, internal_data: InternalData) -> bool:
        return True


class AlwaysFalse(BaseCondition):
    name: Literal["always_false"] = "always_false"

    def check(self, internal_data: InternalData) -> bool:
        return False


Condition = Annotated[
    Union[
        IsContainedInStaticList,
        RegexMatch,
        NotOperator,
        OrComposition,
        AndComposition,
        AlwaysTrue,
        AlwaysFalse,
    ],
    Field(..., discriminator="name"),
]


class Predicate(BaseModel):
    condition: Condition

    def check(self, internal_data: InternalData) -> bool:
        return self.condition.check(internal_data)


OrComposition.update_forward_refs()
AndComposition.update_forward_refs()
NotOperator.update_forward_refs()
