"""Read-only reference and delta analysis for a controlled Area no-op Save."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

import orjson

from .goat_map_area_merge import (
    _artifact_snapshot,
    _capture_special_snapshot,
    _observer_snapshot,
    _request_on_mi,
    _serial_three_type_zero,
    _type_selected,
)
from .goat_map_area_rename_restore import (
    _cycle_family_comparison,
    _restore_snapshot_checks,
    _role_comparison_review,
    _stable_area_across_post_windows,
)
from .goat_map_delta import (
    ArtifactDeltaError,
    VerifiedPhase2Artifact,
    load_verified_phase2_artifact,
)

if TYPE_CHECKING:
    from pathlib import Path

    from .goat_map_area_split import AreaSplitEvidenceObserver

_P2_12C_CAPTURE_ID = "12f3b733c49748ebb41e9f6f99dca307"
_EXPECTED_C_AREA_AR = {
    "status": "stable",
    "infoSize": 286,
    "representation": {
        "length": 124,
        "sha256": "472b23f62fd4f8370dfcd242b54e966cf54463523f30bb20cbd52ce8110d23ba",
    },
    "strict_base64_derived": {
        "status": "strict-base64-round-trip-proven",
        "length": 91,
        "sha256": "0e29d87d42afae28ee3c8ee85d9aebd5cf3c18c404c4249661ec458fbd47cc31",
    },
}
_EXPECTED_C_ON_ARI = {
    "mid": "1",
    "type": "0",
    "serial": 3,
    "info_size": 6933,
    "derived_length": 1651,
    "derived_sha256": "46a2843dcc5595a83d68c378cd51c534d8310315db0967fc016d0647dc9a8c97",
    "context_signature_hex": "c8c9b157b2874a80dcc06c3923718e503b",
}
_EXPECTED_C_ON_MI = {
    "association": "request-associated",
    "mid": "1",
    "info_size": 1756,
    "original_length": 876,
    "original_sha256": "12cbcb330c3b91334f72b41470e09361310853554f8292bc83e4dd72dfbdd5bb",
}
_EXPECTED_C_VW = {
    "mid": "1",
    "aid": "0",
    "type": "vw",
    "info_size": 2,
    "subsets_length": 24,
    "subsets_sha256": "1e01a6d271fbf47823e02e56d20cdf2a8db654afb1d11f703ed3a49d255c1255",
}


class AreaNoOpSaveReferenceError(ValueError):
    """The immutable P2-12c reference is incomplete or unexpected."""


@dataclass(frozen=True, slots=True)
class AreaNoOpSaveReference:
    """Verified current C-state derived from immutable P2-12c."""

    capture_id: str
    phase: str
    state: dict[str, Any]


def load_area_noop_save_reference(
    artifact_dir: Path,
    *,
    expected_capture_id: str = _P2_12C_CAPTURE_ID,
) -> AreaNoOpSaveReference:
    """Verify immutable P2-12c and derive its stable post-restore C-state."""
    artifact = _verified_artifact(artifact_dir)
    if artifact.capture_id != expected_capture_id:
        raise AreaNoOpSaveReferenceError("Area no-op Save reference capture mismatch")
    windows = _p2_12c_windows(artifact.phase)
    state = _artifact_snapshot(artifact, (*windows["primary"], windows["reopen"]))
    area = _stable_area_across_post_windows(
        artifact,
        primary_windows=windows["primary"],
        reopen_window=windows["reopen"],
    )
    if not _area_matches_expected(area):
        raise AreaNoOpSaveReferenceError("P2-12c C-state AreaSet ar mismatch")
    for items, expected, label in (
        (_serial_three_type_zero(state["on_ari"]), _EXPECTED_C_ON_ARI, "onArI"),
        (_request_on_mi(state["on_mi"]), _EXPECTED_C_ON_MI, "onMI"),
        (_type_selected(state["area_set"], "vw"), _EXPECTED_C_VW, "AreaSet vw"),
    ):
        if not _all_items_match(items, expected):
            message = f"P2-12c C-state {label} mismatch"
            raise AreaNoOpSaveReferenceError(message)
    if not state["special_contour"]:
        raise AreaNoOpSaveReferenceError("P2-12c C-state SpecialContour missing")
    return AreaNoOpSaveReference(
        capture_id=artifact.capture_id,
        phase=artifact.phase,
        state=state,
    )


def evaluate_area_noop_save_preconditions(  # noqa: PLR0913
    base: Mapping[str, Any],
    evidence: AreaSplitEvidenceObserver,
    *,
    init_1_window: str,
    init_2_window: str,
    reference: AreaNoOpSaveReference,
    capture_records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Open the no-op Save gate only for two exact P2-12c C-state readbacks."""
    result = cast("dict[str, Any]", orjson.loads(orjson.dumps(base)))
    failures = list(result["failures"])
    first = _observer_snapshot(evidence, (init_1_window,))
    second = _observer_snapshot(evidence, (init_2_window,))
    first["special_contour"] = _capture_special_snapshot(
        capture_records, (init_1_window,)
    )
    second["special_contour"] = _capture_special_snapshot(
        capture_records, (init_2_window,)
    )
    checks = _restore_snapshot_checks(first, second, reference.state)
    for name, check in checks.items():
        if check["status"] != "passed":
            failures.append(
                {"check": f"p2-12c-c-state-{name}", "reason": check["reason"]}
            )
    passed = not failures
    result["checks"]["p2_12c_c_state"] = checks
    result["status"] = "passed" if passed else "inconclusive"
    result["result"] = "precondition-passed" if passed else "precondition-failed"
    result["split_edit_gate_open"] = False
    result["noop_save_edit_gate_open"] = passed
    result["failures"] = failures
    result["reference"] = {
        "capture_id": reference.capture_id,
        "phase": reference.phase,
        "state": "P2-12c-post-restore-C",
        "artifact_verified": True,
        "artifact_modified": False,
    }
    return result


def analyze_area_noop_save_artifact(
    artifact_dir: Path,
    *,
    p2_12c_artifact_dir: Path,
    report: Mapping[str, Any],
    expected_p2_12c_capture_id: str = _P2_12C_CAPTURE_ID,
) -> dict[str, Any]:
    """Compare finalized no-op Save bytes while keeping role coverage separate."""
    current = _verified_artifact(artifact_dir)
    reference_artifact = _verified_artifact(p2_12c_artifact_dir)
    reference = load_area_noop_save_reference(
        p2_12c_artifact_dir,
        expected_capture_id=expected_p2_12c_capture_id,
    )
    controlled = report.get("controlled_area_noop_save")
    if not isinstance(controlled, Mapping):
        raise AreaNoOpSaveReferenceError("P2-13 controlled report is missing")
    windows = _p2_13_windows(current.phase)
    primary = _artifact_snapshot(current, windows["primary"])
    reopen = _artifact_snapshot(current, (windows["reopen"],))
    combined = _artifact_snapshot(current, (*windows["primary"], windows["reopen"]))
    role_review = _role_comparison_review(reference.state, primary, reopen)

    before_area = _stable_area_across_post_windows(
        reference_artifact,
        primary_windows=_p2_12c_windows(reference.phase)["primary"],
        reopen_window=_p2_12c_windows(reference.phase)["reopen"],
    )
    after_area = _stable_area_across_post_windows(
        current,
        primary_windows=windows["primary"],
        reopen_window=windows["reopen"],
    )
    area_delta = classify_noop_save_area_delta(before_area, after_area)
    family_comparisons = _cycle_family_comparison(
        reference.state,
        reference.state,
        combined,
    )
    precondition = controlled.get("precondition")
    precondition_passed = (
        isinstance(precondition, Mapping) and precondition.get("status") == "passed"
    )
    execution_completed = controlled.get("state") == "completed" and precondition_passed
    area_comparable = area_delta["classification"] != "not-comparable"
    experiment_status, delta_status = _noop_save_statuses(
        execution_completed=execution_completed,
        area_comparable=area_comparable,
    )
    return {
        "schema_version": "goat-area-noop-save-analysis/v1",
        "analysis_version": "goat-area-noop-save/1.0.0",
        "analysis_kind": "controlled-no-user-data-change-structural-comparison",
        "source_artifacts": {
            "P2-12c": {
                "capture_id": reference.capture_id,
                "artifact_verified": True,
                "artifact_modified": False,
            },
            "P2-13": {
                "capture_id": current.capture_id,
                "artifact_verified": True,
                "artifact_modified": False,
            },
        },
        "experiment_status": experiment_status,
        "delta_status": delta_status,
        "write_attribution": controlled.get("write_attribution"),
        "role_comparison": role_review,
        "AreaSet_ar_delta": area_delta,
        "family_comparisons": family_comparisons,
        "operator_control": {
            "operation": "area-no-op-save",
            "user_data_change_intended": False,
            "operator_safety_confirmation_required": True,
        },
        "interpretation_limits": {
            "outbound_write_required_for_delta_validity": False,
            "save_ineffective_inferred_from_missing_write": False,
            "family_separation_is_structural_only": True,
            "semantic_parser": False,
            "geometry_interpretation": False,
        },
    }


def classify_noop_save_area_delta(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> dict[str, Any]:
    """Classify only byte/metadata equality for stable AreaSet ar states."""
    comparable = before.get("status") == after.get("status") == "stable"
    fields = ("infoSize", "representation", "strict_base64_derived")
    if not comparable:
        classification = "not-comparable"
    elif all(before.get(field) == after.get(field) for field in fields):
        classification = "no-op-save-no-structural-change"
    else:
        classification = "no-op-save-associated-structural-change"
    return {
        "classification": classification,
        "before_P2_12c_C_state": dict(before),
        "after_P2_13_noop_save_state": dict(after),
        "comparison_layers": [
            "original-representation-bytes",
            "strict-base64-derived-bytes",
            "length",
            "sha256",
            "infoSize",
        ],
        "semantic_mapping": False,
    }


def _noop_save_statuses(
    *,
    execution_completed: bool,
    area_comparable: bool,
) -> tuple[str, str]:
    """Keep AreaSet delta validity independent of family role coverage."""
    experiment_status = "completed-action" if execution_completed else "inconclusive"
    delta_status = (
        "controlled-structural-evidence"
        if execution_completed and area_comparable
        else "not-comparable"
        if not area_comparable
        else "inconclusive"
    )
    return experiment_status, delta_status


def _verified_artifact(path: Path) -> VerifiedPhase2Artifact:
    try:
        return load_verified_phase2_artifact(path)
    except ArtifactDeltaError as err:
        raise AreaNoOpSaveReferenceError(str(err)) from err


def _p2_12c_windows(phase: str) -> dict[str, Any]:
    return {
        "primary": (f"{phase}:restore-save", f"{phase}:post-restore-readback"),
        "reopen": f"{phase}:post-restore-reopen",
    }


def _p2_13_windows(phase: str) -> dict[str, Any]:
    return {
        "primary": (f"{phase}:no-op-save", f"{phase}:post-noop-save-readback"),
        "reopen": f"{phase}:post-noop-save-reopen",
    }


def _area_matches_expected(area: Mapping[str, Any]) -> bool:
    return all(area.get(field) == value for field, value in _EXPECTED_C_AREA_AR.items())


def _all_items_match(
    items: Sequence[Mapping[str, Any]],
    expected: Mapping[str, Any],
) -> bool:
    return bool(items) and all(
        all(item.get(field) == value for field, value in expected.items())
        for item in items
    )
