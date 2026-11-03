"""Pydantic-схемы записей входных фидов."""

import re
from datetime import date
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from kasp.utils.versions import parse

VERSION_RE = re.compile(r"\d+(\.\d+)*")


def _check_version(value: str) -> str:

    if not VERSION_RE.fullmatch(value):
        raise ValueError(f"Invalid version '{value}', use a form like 1.2.3")
    return value


VersionStr = Annotated[str, AfterValidator(_check_version)]
NonEmptyStr = Annotated[str, Field(min_length=1)]


class FeedRecord(BaseModel):
    """Поля, общие для записей обоих фидов."""

    model_config = ConfigDict(str_strip_whitespace=True, populate_by_name=True)

    vendor: NonEmptyStr
    product: NonEmptyStr


class VersionRecord(FeedRecord):
    """Запись фида версии."""

    version: VersionStr


class VulnerabilityRecord(FeedRecord):
    """Запись фида уязвимости."""

    kla_id: NonEmptyStr = Field(alias="KLA_id")
    description: NonEmptyStr
    pub_date: date = Field(alias="publish_date")
    start_version: VersionStr = Field(alias="start_vuln_version")
    fixed_version: VersionStr

    @model_validator(mode="after")
    def _check_range(self) -> "VulnerabilityRecord":
        """Проверка что уязвимая < пофикшенной версии"""
        if parse(self.start_version) > parse(self.fixed_version):
            raise ValueError(
                "start_vuln_version must not be greater than fixed_version, "
                f"got {self.start_version} and {self.fixed_version}"
            )
        return self
