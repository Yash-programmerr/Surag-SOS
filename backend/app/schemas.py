from datetime import date, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class ChangeType(StrEnum):
    construction = "construction"
    clearance = "clearance"
    water_variation = "water_variation"
    road_development = "road_development"
    no_change = "no_change"
    unknown = "unknown"


class JobState(StrEnum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class AnalysisRequest(BaseModel):
    aoi: dict[str, Any] = Field(description="GeoJSON Polygon or MultiPolygon")
    start_date: date
    end_date: date
    change_types: list[ChangeType] = Field(default_factory=lambda: list(ChangeType))
    max_cloud_cover: float = Field(default=20, ge=0, le=100)

    @model_validator(mode="after")
    def valid_dates_and_aoi(self):
        if self.start_date >= self.end_date:
            raise ValueError("start_date must precede end_date")
        if self.aoi.get("type") not in {"Polygon", "MultiPolygon"}:
            raise ValueError("aoi must be a GeoJSON Polygon or MultiPolygon")
        return self


class Job(BaseModel):
    id: UUID
    analysis_id: UUID
    state: JobState
    progress: int = Field(ge=0, le=100)
    detail: str
    created_at: datetime


class Provenance(BaseModel):
    source_scenes: list[str]
    preprocessing_version: str
    model_name: str
    model_version: str
    model_checksum: str
    policy_version: str


class ChangeResult(BaseModel):
    id: UUID
    analysis_id: UUID
    change_type: ChangeType
    confidence: float
    occurred_between: tuple[date, date]
    earliest_supported_observation: date
    geometry: dict[str, Any]
    preview_before: str
    preview_after: str
    rationale: list[str]
    provenance: Provenance
    review_status: Literal["unreviewed", "confirmed", "rejected"] = "unreviewed"
    reviewer_note: str | None = None


class ReviewRequest(BaseModel):
    decision: Literal["confirmed", "rejected"]
    note: str | None = Field(default=None, max_length=2000)


class SearchRequest(BaseModel):
    query: str = Field(min_length=3, max_length=500)
    aoi: dict[str, Any] | None = None
    start_date: date | None = None
    end_date: date | None = None
