from uuid import uuid4

from .schemas import AnalysisRequest, ChangeResult, ChangeType, Provenance


def demo_results(analysis_id, request: AnalysisRequest):
    """Clearly marked demo data; replace with the EO/ML layer when available."""
    request_types = [ChangeType.construction, ChangeType.water_variation]
    provenance = Provenance(
        source_scenes=[], preprocessing_version="not-run", model_name="demo-fixture", model_version="0.1.0",
        model_checksum="not-applicable", policy_version="demo-only",
    )
    results = []
    for index, change_type in enumerate(change_type for change_type in request_types if change_type in request.change_types):
        result = ChangeResult(
            id=uuid4(), analysis_id=analysis_id, change_type=change_type,
            confidence=0.94 - index * 0.12,
            occurred_between=(request.start_date, request.end_date),
            earliest_supported_observation=request.end_date,
            geometry=request.aoi,
            preview_before="", preview_after="",
            rationale=["Synthetic demonstration result; no satellite imagery or ML model was run"],
            provenance=provenance,
        )
        results.append(result)
    return results
