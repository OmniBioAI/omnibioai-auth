"""Validated public and administrative research-inquiry contracts."""

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


ResearchInterest = Literal[
    "biomedical_literature_ai", "genomics_precision_medicine", "cancer_research",
    "multi_omics", "biomedical_ai_evaluation", "scientific_workflows",
    "biomedical_knowledge_graphs", "other",
]
InquiryStatus = Literal["new", "in_review", "contacted", "closed", "spam"]


class ResearchInquiryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    full_name: str = Field(min_length=1, max_length=120)
    institutional_email: str = Field(min_length=3, max_length=254)
    institution: str = Field(min_length=1, max_length=200)
    department: str = Field(min_length=1, max_length=160)
    country: str = Field(min_length=1, max_length=100)
    research_interest: ResearchInterest
    proposed_collaboration: str = Field(min_length=1, max_length=4000)
    potential_datasets: str = Field(default="", max_length=2500)
    institutional_website: str = Field(default="", max_length=500)
    additional_information: str = Field(default="", max_length=2500)
    consent: Literal[True]
    company_fax: str = Field(default="", max_length=100)

    @field_validator("consent", mode="before")
    @classmethod
    def explicit_consent(cls, value):
        if value is not True:
            raise ValueError("Explicit boolean consent is required")
        return value

    @field_validator("*", mode="before")
    @classmethod
    def safe_text(cls, value, info):
        if isinstance(value, str):
            multiline = info.field_name in {"proposed_collaboration", "potential_datasets", "additional_information"}
            pattern = r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff]" if multiline else r"[\x00-\x1f\x7f\ud800-\udfff]"
            if re.search(pattern, value):
                raise ValueError("Unsupported control characters")
            return value.replace("\r\n", "\n").replace("\r", "\n")
        return value

    @field_validator("full_name", "institution", "department", "country", mode="before")
    @classmethod
    def compact_text(cls, value):
        # Control validation runs after this validator: never erase CR/LF here.
        return re.sub(r" +", " ", value.strip(" ")) if isinstance(value, str) else value


class ResearchInquiryStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: InquiryStatus
