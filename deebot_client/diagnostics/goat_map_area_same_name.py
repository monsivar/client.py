"""Controlled same-value Area rename resubmission research helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from .goat_map_area_merge import _artifact_snapshot
from .goat_map_area_noop_save import (
    AreaNoOpSaveReference,
    evaluate_area_noop_save_preconditions,
    load_area_noop_save_reference,
)
from .goat_map_area_rename import _verified_record_shape
from .goat_map_area_rename_restore import (
    _cycle_family_comparison,
    _request_records,
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
_P2_11_CAPTURE_ID = "861a4bfd6d1f4fa9b0b24e370c6e2454"


class AreaSameNameReferenceError(ValueError):
    """A same-name reference artifact is incomplete or unexpected."""


def evaluate_area_same_name_preconditions(  # noqa: PLR0913
    base: Mapping[str, Any],
    evidence: AreaSplitEvidenceObserver,
    *,
    init_1_window: str,
    init_2_window: str,
    reference: AreaNoOpSaveReference,
    capture_records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Open only the same-name gate after two exact P2-12c C readbacks."""
    result = evaluate_area_noop_save_preconditions(
        base,
        evidence,
        init_1_window=init_1_window,
        init_2_window=init_2_window,
        reference=reference,
        capture_records=capture_records,
    )
    passed = result["status"] == "passed"
    result["noop_save_edit_gate_open"] = False
    result["same_name_resubmission_edit_gate_open"] = passed
    result["reference"]["state"] = "P2-12c-post-restore-C-before-same-name"
    return result


def analyze_area_same_name_artifact(  # noqa: PLR0913
    artifact_dir: Path,
    *,
    p2_12c_artifact_dir: Path,
    p2_11_artifact_dir: Path,
    report: Mapping[str, Any],
    expected_p2_12c_capture_id: str = _P2_12C_CAPTURE_ID,
    expected_p2_11_capture_id: str = _P2_11_CAPTURE_ID,
) -> dict[str, Any]:
    """Compare stable before/after bytes without treating the action as a no-op."""
    current = _verified_artifact(artifact_dir)
    reference_artifact = _verified_artifact(p2_12c_artifact_dir)
    reference = load_area_noop_save_reference(
        p2_12c_artifact_dir,
        expected_capture_id=expected_p2_12c_capture_id,
    )
    controlled = report.get("controlled_area_same_name_resubmission")
    if not isinstance(controlled, Mapping):
        raise AreaSameNameReferenceError("P2-13b controlled report is missing")
    windows = _same_name_windows(current.phase)
    primary = _artifact_snapshot(current, windows["primary"])
    reopen = _artifact_snapshot(current, (windows["reopen"],))
    combined = _artifact_snapshot(current, (*windows["primary"], windows["reopen"]))
    role_review = _role_comparison_review(reference.state, primary, reopen)

    reference_windows = _p2_12c_windows(reference.phase)
    before_area = _stable_area_across_post_windows(
        reference_artifact,
        primary_windows=reference_windows["primary"],
        reopen_window=reference_windows["reopen"],
    )
    after_area = _stable_area_across_post_windows(
        current,
        primary_windows=windows["primary"],
        reopen_window=windows["reopen"],
    )
    area_delta = classify_same_name_area_delta(before_area, after_area)
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
    experiment_status, delta_status = _same_name_statuses(
        execution_completed=execution_completed,
        area_comparable=area_comparable,
    )
    write = controlled.get("write_attribution")
    authoritative_command = (
        write.get("authoritative_command") if isinstance(write, Mapping) else None
    )
    write_shape = _same_name_write_shape_comparison(
        current,
        reference_artifact,
        p2_11_artifact_dir,
        expected_p2_11_capture_id=expected_p2_11_capture_id,
        authoritative_command=authoritative_command,
        action_windows={windows["edit"], windows["save"]},
    )
    return {
        "schema_version": "goat-area-same-name-resubmission-analysis/v1",
        "analysis_version": "goat-area-same-name-resubmission/1.0.0",
        "analysis_kind": "controlled-same-visible-value-metadata-resubmission",
        "source_artifacts": {
            "P2-12c": {
                "capture_id": reference.capture_id,
                "artifact_verified": True,
                "artifact_modified": False,
            },
            "P2-13b": {
                "capture_id": current.capture_id,
                "artifact_verified": True,
                "artifact_modified": False,
            },
        },
        "experiment_status": experiment_status,
        "delta_status": delta_status,
        "write_attribution": write,
        "role_comparison": role_review,
        "AreaSet_ar_delta": area_delta,
        "family_comparisons": family_comparisons,
        "write_shape_comparison": write_shape,
        "operator_control": {
            "operation": "same-value-rename-resubmission",
            "old_utf8_byte_length": 5,
            "submitted_utf8_byte_length": 5,
            "visible_values_equal": True,
            "actual_name_stored_in_report": False,
            "not_a_noop": True,
        },
        "interpretation_limits": {
            "name_located_in_AreaSet_ar": False,
            "equal_visible_values_imply_equal_internal_semantics": False,
            "family_separation_is_structural_only": True,
            "semantic_parser": False,
            "geometry_interpretation": False,
        },
    }


def classify_same_name_area_delta(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> dict[str, Any]:
    """Classify stable AreaSet ar equality after same-value resubmission."""
    comparable = before.get("status") == after.get("status") == "stable"
    fields = ("infoSize", "representation", "strict_base64_derived")
    if not comparable:
        classification = "not-comparable"
    elif all(before.get(field) == after.get(field) for field in fields):
        classification = "same-value-resubmission-no-structural-change"
    else:
        classification = "same-value-resubmission-associated-structural-change"
    return {
        "classification": classification,
        "A_P2_12c_stable_C_state": dict(before),
        "B_P2_13b_post_resubmission_state": dict(after),
        "comparison_layers": [
            "original-representation-bytes",
            "strict-base64-derived-bytes",
            "length",
            "sha256",
            "infoSize",
        ],
        "semantic_mapping": False,
    }


def _same_name_statuses(
    *,
    execution_completed: bool,
    area_comparable: bool,
) -> tuple[str, str]:
    experiment_status = "completed-action" if execution_completed else "inconclusive"
    delta_status = (
        "controlled-structural-evidence"
        if execution_completed and area_comparable
        else "not-comparable"
        if not area_comparable
        else "inconclusive"
    )
    return experiment_status, delta_status


def _same_name_write_shape_comparison(  # noqa: PLR0913
    current: VerifiedPhase2Artifact,
    p2_12c: VerifiedPhase2Artifact,
    p2_11_artifact_dir: Path,
    *,
    expected_p2_11_capture_id: str,
    authoritative_command: Any,
    action_windows: set[str],
) -> dict[str, Any]:
    if authoritative_command != "setAreaSet":
        return {"status": "not-applicable", "reason": "write-is-not-setAreaSet"}
    p2_11 = _verified_artifact(p2_11_artifact_dir)
    if p2_11.capture_id != expected_p2_11_capture_id:
        raise AreaSameNameReferenceError("P2-11 write-shape capture mismatch")
    current_records = _request_records(current, action_windows)
    rename_records = _request_records(p2_11, None)
    restore_records = _request_records(p2_12c, None)
    if any(len(records) != 1 for records in (current_records, rename_records, restore_records)):
        return {
            "status": "not-comparable",
            "P2_13b_count": len(current_records),
            "P2_11_count": len(rename_records),
            "P2_12c_count": len(restore_records),
        }
    return {
        "status": "comparable",
        "P2_13b_same_name": _verified_record_shape(current_records[0]),
        "P2_11_rename": _verified_record_shape(rename_records[0]),
        "P2_12c_restore": _verified_record_shape(restore_records[0]),
        "command_shape_evidence_only": True,
        "semantic_mapping": False,
    }


def _verified_artifact(path: Path) -> VerifiedPhase2Artifact:
    try:
        return load_verified_phase2_artifact(path)
    except ArtifactDeltaError as err:
        raise AreaSameNameReferenceError(str(err)) from err


def _p2_12c_windows(phase: str) -> dict[str, Any]:
    return {
        "primary": (f"{phase}:restore-save", f"{phase}:post-restore-readback"),
        "reopen": f"{phase}:post-restore-reopen",
    }


def _same_name_windows(phase: str) -> dict[str, Any]:
    return {
        "edit": f"{phase}:same-name-edit",
        "save": f"{phase}:same-name-save",
        "primary": (f"{phase}:same-name-save", f"{phase}:post-same-name-readback"),
        "reopen": f"{phase}:post-same-name-reopen",
    }


__all__ = [
    "AreaSameNameReferenceError",
    "analyze_area_same_name_artifact",
    "classify_same_name_area_delta",
    "evaluate_area_same_name_preconditions",
]
