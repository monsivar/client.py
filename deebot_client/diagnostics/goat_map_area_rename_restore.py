"""Read-only status and inverse-control analysis for GOAT Area rename research."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import TYPE_CHECKING, Any, cast

import orjson

from .goat_map_area_merge import (
    _artifact_snapshot,
    _capture_special_snapshot,
    _observer_snapshot,
    _record_data,
    _request_on_mi,
    _segment,
    _segment_int,
    _serial_three_type_zero,
    _type_selected,
)
from .goat_map_area_rename import (
    _ON_ARI_VALUE_FIELDS,
    _ON_MI_VALUE_FIELDS,
    _verified_record_shape,
)
from .goat_map_delta import (
    ArtifactDeltaError,
    VerifiedPhase2Artifact,
    load_verified_phase2_artifact,
)
from .goat_map_representation import (
    RepresentationDecodeError,
    decode_strict_base64_representation,
)

if TYPE_CHECKING:
    from pathlib import Path

    from .goat_map_area_split import AreaSplitEvidenceObserver

_P2_11_CAPTURE_ID = "861a4bfd6d1f4fa9b0b24e370c6e2454"
_P2_09C_CAPTURE_ID = "212a37d365b54f77bbb6c0424ff94246"
_CONCLUSION = (
    "Area Rename produced a stable value change in AreaSet ar, while directly "
    "comparable grouped onArI serial=3/type=0, request-associated onMI, vw, mid "
    "and comparable SpecialContour values remained byte-identical."
)
_AREA_VALUE_FIELDS = ("info_size", "subsets_length", "subsets_sha256")
_SPECIAL_VALUE_FIELDS = ("byte_length", "sha256")
_EXPECTED_B_AREA_AR = {
    "mid": "1",
    "aid": "0",
    "type": "ar",
    "info_size": 286,
    "subsets_length": 124,
    "subsets_sha256": "95f8e54faf889ce346bc58bc6ce479f1ba9c5aded40439c79c0186c90b17c8e1",
}
_EXPECTED_B_ON_ARI = {
    "mid": "1",
    "type": "0",
    "serial": 3,
    "info_size": 6933,
    "derived_length": 1651,
    "derived_sha256": "46a2843dcc5595a83d68c378cd51c534d8310315db0967fc016d0647dc9a8c97",
    "context_signature_hex": "c8c9b157b2874a80dcc06c3923718e503b",
}
_EXPECTED_B_ON_MI = {
    "association": "request-associated",
    "mid": "1",
    "info_size": 1756,
    "original_length": 876,
    "original_sha256": "12cbcb330c3b91334f72b41470e09361310853554f8292bc83e4dd72dfbdd5bb",
}
_EXPECTED_B_VW = {
    "mid": "1",
    "aid": "0",
    "type": "vw",
    "info_size": 2,
    "subsets_length": 24,
    "subsets_sha256": "1e01a6d271fbf47823e02e56d20cdf2a8db654afb1d11f703ed3a49d255c1255",
}


class AreaRenameRestoreReferenceError(ValueError):
    """The immutable P2-11 rename reference is incomplete or unexpected."""


@dataclass(frozen=True, slots=True)
class AreaRenameRestoreReference:
    """Verified A/B structural snapshots from immutable P2-11."""

    capture_id: str
    phase: str
    a_state: dict[str, Any]
    b_state: dict[str, Any]


def build_area_rename_status_review(
    artifact_dir: Path,
    original_summary: Path,
    *,
    expected_capture_id: str = _P2_11_CAPTURE_ID,
) -> dict[str, Any]:
    """Build a derived v2 P2-11 status review without modifying either source."""
    artifact = _verified_artifact(artifact_dir)
    if artifact.capture_id != expected_capture_id:
        raise AreaRenameRestoreReferenceError("P2-11 status-review capture ID mismatch")
    try:
        summary_raw = original_summary.read_bytes()
        summary = orjson.loads(summary_raw)
    except (FileNotFoundError, orjson.JSONDecodeError) as err:
        raise AreaRenameRestoreReferenceError("P2-11 original summary is invalid") from err
    if not isinstance(summary, dict):
        raise AreaRenameRestoreReferenceError("P2-11 original summary is not an object")
    manifest = summary.get("phase2_capture")
    controlled = summary.get("controlled_area_rename")
    if not isinstance(manifest, dict) or manifest.get("capture_id") != artifact.capture_id:
        raise AreaRenameRestoreReferenceError("P2-11 summary/artifact provenance mismatch")
    if not isinstance(controlled, dict):
        raise AreaRenameRestoreReferenceError("P2-11 controlled rename report is missing")

    windows = _p2_11_windows(artifact.phase)
    before = _artifact_snapshot(artifact, (windows["before"],))
    primary = _artifact_snapshot(artifact, windows["primary"])
    reopen = _artifact_snapshot(artifact, (windows["reopen"],))
    role_review = _role_comparison_review(before, primary, reopen)
    area_before = _area_state(artifact, (windows["before"],))
    area_primary = _area_state(artifact, windows["primary"])
    area_reopen = _area_state(artifact, (windows["reopen"],))
    stable_area_delta = (
        area_before["status"] == "stable"
        and area_primary["status"] == "stable"
        and area_reopen["status"] == "stable"
        and area_primary["representation"]["sha256"]
        == area_reopen["representation"]["sha256"]
        and area_before["representation"]["sha256"]
        != area_primary["representation"]["sha256"]
    )
    if not stable_area_delta:
        raise AreaRenameRestoreReferenceError("P2-11 stable AreaSet ar delta missing")

    write = controlled.get("write_attribution")
    rename_analysis = controlled.get("rename_analysis")
    shape = (
        rename_analysis.get("setAreaSet_request_shape_vs_divide")
        if isinstance(rename_analysis, dict)
        else None
    )
    return {
        "schema_version": "goat-area-rename-status-review/v2",
        "analysis_version": "goat-area-rename-status-review/2.0.0",
        "analysis_kind": "derived-read-only-status-review",
        "source_artifact": {
            "capture_id": artifact.capture_id,
            "phase": artifact.phase,
            "artifact_verified": True,
            "artifact_modified": False,
        },
        "source_summary": {
            "filename": original_summary.name,
            "sha256": sha256(summary_raw).hexdigest(),
            "disposition": "superseded-for-status-only",
            "source_file_modified": False,
            "original_experiment_status": controlled.get("experiment_status"),
            "original_delta_status": controlled.get("delta_status"),
        },
        "experiment_status": "completed-action",
        "delta_status": "controlled-partial-structural-evidence",
        "write_attribution": write,
        "area_set_rename_delta": {
            "status": "controlled-structural-evidence",
            "before": area_before,
            "primary_post_save": area_primary,
            "reopen": area_reopen,
            "primary_and_reopen_byte_identical": True,
        },
        "role_comparison": role_review,
        "write_shape_observation": {
            "status": shape.get("status") if isinstance(shape, dict) else None,
            "rename_command": (
                write.get("authoritative_command") if isinstance(write, dict) else None
            ),
            "rename_observed_subset_fields": ["act", "mssid", "name", "type"],
            "divide_observed_subset_fields": ["act", "mssid", "type", "value"],
            "command_shape_evidence_only": True,
            "semantic_mapping": False,
        },
        "conclusion": _CONCLUSION,
        "interpretation_limits": {
            "name_located_in_AreaSet_ar": False,
            "generic_save_or_edit_generation_remains_alternative": True,
            "missing_roles_fabricated": False,
            "semantic_parser": False,
            "geometry_interpretation": False,
        },
    }


def load_area_rename_restore_reference(
    artifact_dir: Path,
    *,
    expected_capture_id: str = _P2_11_CAPTURE_ID,
) -> AreaRenameRestoreReference:
    """Verify immutable P2-11 and derive its original A and renamed B states."""
    artifact = _verified_artifact(artifact_dir)
    if artifact.capture_id != expected_capture_id:
        raise AreaRenameRestoreReferenceError("Area rename-restore capture ID mismatch")
    windows = _p2_11_windows(artifact.phase)
    a_state = _artifact_snapshot(artifact, (windows["before"],))
    b_primary = _artifact_snapshot(artifact, windows["primary"])
    b_state = _artifact_snapshot(artifact, (windows["reopen"],))
    _validate_p2_11_b_state(b_primary, b_state)
    return AreaRenameRestoreReference(
        capture_id=artifact.capture_id,
        phase=artifact.phase,
        a_state=a_state,
        b_state=b_state,
    )


def evaluate_area_rename_restore_preconditions(  # noqa: PLR0913
    base: Mapping[str, Any],
    evidence: AreaSplitEvidenceObserver,
    *,
    init_1_window: str,
    init_2_window: str,
    reference: AreaRenameRestoreReference,
    capture_records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Open the restore gate only for two exact reproductions of P2-11 B-state."""
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
    checks = _restore_snapshot_checks(first, second, reference.b_state)
    for name, check in checks.items():
        if check["status"] != "passed":
            failures.append(
                {"check": f"p2-11-b-state-{name}", "reason": check["reason"]}
            )
    passed = not failures
    result["checks"]["p2_11_b_state"] = checks
    result["status"] = "passed" if passed else "inconclusive"
    result["result"] = "precondition-passed" if passed else "precondition-failed"
    result["split_edit_gate_open"] = False
    result["rename_edit_gate_open"] = False
    result["rename_restore_edit_gate_open"] = passed
    result["failures"] = failures
    result["reference"] = {
        "capture_id": reference.capture_id,
        "phase": reference.phase,
        "state": "P2-11-post-rename-B",
        "artifact_verified": True,
        "artifact_modified": False,
    }
    return result


def analyze_area_rename_restore_artifact(  # noqa: PLR0913
    artifact_dir: Path,
    *,
    p2_11_artifact_dir: Path,
    divide_artifact_dir: Path,
    report: Mapping[str, Any],
    expected_p2_11_capture_id: str = _P2_11_CAPTURE_ID,
    expected_divide_capture_id: str = _P2_09C_CAPTURE_ID,
) -> dict[str, Any]:
    """Analyze finalized P2-12 bytes while keeping role coverage independent."""
    current = _verified_artifact(artifact_dir)
    reference_artifact = _verified_artifact(p2_11_artifact_dir)
    reference = load_area_rename_restore_reference(
        p2_11_artifact_dir,
        expected_capture_id=expected_p2_11_capture_id,
    )
    controlled = report.get("controlled_area_rename_restore")
    if not isinstance(controlled, Mapping):
        raise AreaRenameRestoreReferenceError("P2-12 controlled report is missing")
    windows = _restore_windows(current.phase)
    primary = _artifact_snapshot(current, windows["primary"])
    reopen = _artifact_snapshot(current, (windows["reopen"],))
    combined = _artifact_snapshot(current, (*windows["primary"], windows["reopen"]))
    role_review = _role_comparison_review(reference.b_state, primary, reopen)

    a_area = _area_state(reference_artifact, (f"{reference.phase}:pre-rename-app-init-2",))
    b_area = _area_state(
        reference_artifact,
        (
            f"{reference.phase}:rename-save",
            f"{reference.phase}:post-rename-readback",
            f"{reference.phase}:post-rename-reopen",
        ),
    )
    c_area = _stable_area_across_post_windows(
        current,
        primary_windows=windows["primary"],
        reopen_window=windows["reopen"],
    )
    three_state = _three_state_area_analysis(a_area, b_area, c_area)
    cycle = _cycle_family_comparison(reference.a_state, reference.b_state, combined)
    area_comparable = three_state["classification"] != "not-comparable"
    role_complete = role_review["status"] == "complete"
    precondition = controlled.get("precondition")
    precondition_passed = (
        isinstance(precondition, Mapping) and precondition.get("status") == "passed"
    )
    execution_completed = controlled.get("state") == "completed" and precondition_passed
    experiment_status, delta_status = _restore_statuses(
        execution_completed=execution_completed,
        area_comparable=area_comparable,
        role_complete=role_complete,
    )
    write = controlled.get("write_attribution")
    shape = _restore_write_shape_comparison(
        current,
        reference_artifact,
        divide_artifact_dir,
        expected_divide_capture_id=expected_divide_capture_id,
        authoritative_command=(
            write.get("authoritative_command") if isinstance(write, Mapping) else None
        ),
        restore_windows={windows["edit"], windows["save"]},
    )
    return {
        "schema_version": "goat-area-rename-restore-analysis/v1",
        "analysis_version": "goat-area-rename-restore/1.0.0",
        "analysis_kind": "controlled-three-state-structural-comparison",
        "source_artifacts": {
            "P2-11": {
                "capture_id": reference.capture_id,
                "artifact_verified": True,
                "artifact_modified": False,
            },
            "P2-12": {
                "capture_id": current.capture_id,
                "artifact_verified": True,
                "artifact_modified": False,
            },
        },
        "experiment_status": experiment_status,
        "delta_status": delta_status,
        "write_attribution": write,
        "role_comparison": role_review,
        "family_comparisons": cycle,
        "AreaSet_ar_three_state": three_state,
        "write_shape_comparison": shape,
        "operator_control": {
            "operation": "rename-restore",
            "old_utf8_byte_length": 5,
            "new_utf8_byte_length": 5,
            "actual_names_recorded": False,
        },
        "interpretation_limits": {
            "name_located_in_AreaSet_ar": False,
            "generic_save_or_edit_generation_remains_alternative": True,
            "family_separation_is_structural_only": True,
            "semantic_parser": False,
            "geometry_interpretation": False,
        },
    }


def _verified_artifact(path: Path) -> VerifiedPhase2Artifact:
    try:
        return load_verified_phase2_artifact(path)
    except ArtifactDeltaError as err:
        raise AreaRenameRestoreReferenceError(str(err)) from err


def _restore_statuses(
    *,
    execution_completed: bool,
    area_comparable: bool,
    role_complete: bool,
) -> tuple[str, str]:
    experiment_status = "completed-action" if execution_completed else "inconclusive"
    if execution_completed and area_comparable:
        delta_status = (
            "controlled-structural-evidence"
            if role_complete
            else "controlled-partial-structural-evidence"
        )
    else:
        delta_status = "not-comparable" if not area_comparable else "inconclusive"
    return experiment_status, delta_status


def _p2_11_windows(phase: str) -> dict[str, Any]:
    return {
        "before": f"{phase}:pre-rename-app-init-2",
        "primary": (f"{phase}:rename-save", f"{phase}:post-rename-readback"),
        "reopen": f"{phase}:post-rename-reopen",
    }


def _restore_windows(phase: str) -> dict[str, Any]:
    return {
        "edit": f"{phase}:restore-edit",
        "save": f"{phase}:restore-save",
        "primary": (f"{phase}:restore-save", f"{phase}:post-restore-readback"),
        "reopen": f"{phase}:post-restore-reopen",
    }


def _validate_p2_11_b_state(
    primary: Mapping[str, Any],
    reopen: Mapping[str, Any],
) -> None:
    primary_ar = _type_selected(primary["area_set"], "ar")
    reopen_ar = _type_selected(reopen["area_set"], "ar")
    if not _all_expected(primary_ar, _EXPECTED_B_AREA_AR) or not _all_expected(
        reopen_ar, _EXPECTED_B_AREA_AR
    ):
        raise AreaRenameRestoreReferenceError("P2-11 B-state AreaSet ar mismatch")
    for items, expected, label in (
        (_serial_three_type_zero(reopen["on_ari"]), _EXPECTED_B_ON_ARI, "onArI"),
        (_request_on_mi(reopen["on_mi"]), _EXPECTED_B_ON_MI, "onMI"),
        (_type_selected(reopen["area_set"], "vw"), _EXPECTED_B_VW, "AreaSet vw"),
    ):
        if not _all_expected(items, expected):
            message = f"P2-11 B-state {label} mismatch"
            raise AreaRenameRestoreReferenceError(message)
    if not primary["special_contour"] or not reopen["special_contour"]:
        raise AreaRenameRestoreReferenceError("P2-11 B-state SpecialContour missing")
    if _values(primary["special_contour"], ("command", "direction", "source_path"), _SPECIAL_VALUE_FIELDS) != _values(
        reopen["special_contour"], ("command", "direction", "source_path"), _SPECIAL_VALUE_FIELDS
    ):
        raise AreaRenameRestoreReferenceError("P2-11 B-state SpecialContour mismatch")


def _restore_snapshot_checks(
    first: Mapping[str, Any],
    second: Mapping[str, Any],
    reference: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    return {
        "request_associated_onMI": _reference_check(
            _request_on_mi(first["on_mi"]),
            _request_on_mi(second["on_mi"]),
            _request_on_mi(reference["on_mi"]),
            key_fields=("association",),
            value_fields=_ON_MI_VALUE_FIELDS,
        ),
        "AreaSet_ar": _reference_check(
            _type_selected(first["area_set"], "ar"),
            _type_selected(second["area_set"], "ar"),
            _type_selected(reference["area_set"], "ar"),
            key_fields=("mid", "aid", "type"),
            value_fields=_AREA_VALUE_FIELDS,
        ),
        "AreaSet_vw": _reference_check(
            _type_selected(first["area_set"], "vw"),
            _type_selected(second["area_set"], "vw"),
            _type_selected(reference["area_set"], "vw"),
            key_fields=("mid", "aid", "type"),
            value_fields=_AREA_VALUE_FIELDS,
        ),
        "grouped_onArI_serial_3_type_0": _reference_check(
            _serial_three_type_zero(first["on_ari"]),
            _serial_three_type_zero(second["on_ari"]),
            _serial_three_type_zero(reference["on_ari"]),
            key_fields=("mid", "type", "using", "serial"),
            value_fields=_ON_ARI_VALUE_FIELDS,
        ),
        "SpecialContour": _reference_check(
            first["special_contour"],
            second["special_contour"],
            reference["special_contour"],
            key_fields=("command", "direction", "source_path"),
            value_fields=_SPECIAL_VALUE_FIELDS,
        ),
    }


def _reference_check(
    first: Sequence[Mapping[str, Any]],
    second: Sequence[Mapping[str, Any]],
    reference: Sequence[Mapping[str, Any]],
    *,
    key_fields: Sequence[str],
    value_fields: Sequence[str],
) -> dict[str, Any]:
    first_values = _values(first, key_fields, value_fields)
    second_values = _values(second, key_fields, value_fields)
    reference_values = _values(reference, key_fields, value_fields)
    if not first_values or not second_values or not reference_values:
        return {"status": "failed", "reason": "missing-comparable-values"}
    if first_values != second_values:
        return {"status": "failed", "reason": "two-readback-values-differ"}
    if first_values != reference_values:
        return {"status": "failed", "reason": "current-state-does-not-match-p2-11-b"}
    return {"status": "passed", "reason": None, "variant_count": len(first_values)}


def _role_comparison_review(
    before: Mapping[str, Any],
    primary: Mapping[str, Any],
    reopen: Mapping[str, Any],
) -> dict[str, Any]:
    families = {
        "AreaSet_ar": _coverage_family(
            _type_selected(before["area_set"], "ar"),
            _type_selected(primary["area_set"], "ar"),
            _type_selected(reopen["area_set"], "ar"),
            key_fields=("mid", "aid", "type"),
            value_fields=_AREA_VALUE_FIELDS,
        ),
        "AreaSet_vw": _coverage_family(
            _type_selected(before["area_set"], "vw"),
            _type_selected(primary["area_set"], "vw"),
            _type_selected(reopen["area_set"], "vw"),
            key_fields=("mid", "aid", "type"),
            value_fields=_AREA_VALUE_FIELDS,
        ),
        "request_associated_onMI": _coverage_family(
            _request_on_mi(before["on_mi"]),
            _request_on_mi(primary["on_mi"]),
            _request_on_mi(reopen["on_mi"]),
            key_fields=("association",),
            value_fields=_ON_MI_VALUE_FIELDS,
        ),
        "grouped_onArI_serial_3_type_0": _coverage_family(
            _serial_three_type_zero(before["on_ari"]),
            _serial_three_type_zero(primary["on_ari"]),
            _serial_three_type_zero(reopen["on_ari"]),
            key_fields=("mid", "type", "using", "serial"),
            value_fields=_ON_ARI_VALUE_FIELDS,
        ),
        "SpecialContour": _coverage_family(
            before["special_contour"],
            primary["special_contour"],
            reopen["special_contour"],
            key_fields=("command", "direction", "source_path"),
            value_fields=_SPECIAL_VALUE_FIELDS,
        ),
    }
    missing = [
        name
        for name, family in families.items()
        if family["primary_vs_reopen_status"] == "role-overlap-incomplete"
    ]
    conflicts = [
        name
        for name, family in families.items()
        if family["primary_vs_reopen_status"] == "contradictory-values"
    ]
    return {
        "status": "complete" if not missing and not conflicts else "role-comparison-incomplete" if not conflicts else "contradictory-comparable-values",
        "reason": (
            None
            if not missing and not conflicts
            else "missing-role-overlap-not-conflicting-bytes"
            if missing and not conflicts
            else "directly-comparable-values-conflict"
        ),
        "missing_primary_reopen_overlap": missing,
        "contradictory_families": conflicts,
        "contradictory_comparable_bytes": bool(conflicts),
        "families": families,
        "observed_primary_onMI_roles": _on_mi_role_inventory(primary["on_mi"]),
        "observed_reopen_onMI_roles": _on_mi_role_inventory(reopen["on_mi"]),
        "observed_primary_onArI_roles": _on_ari_role_inventory(primary["on_ari"]),
        "observed_reopen_onArI_roles": _on_ari_role_inventory(reopen["on_ari"]),
        "missing_roles_fabricated": False,
    }


def _coverage_family(
    before: Sequence[Mapping[str, Any]],
    primary: Sequence[Mapping[str, Any]],
    reopen: Sequence[Mapping[str, Any]],
    *,
    key_fields: Sequence[str],
    value_fields: Sequence[str],
) -> dict[str, Any]:
    before_values = _values(before, key_fields, value_fields)
    primary_values = _values(primary, key_fields, value_fields)
    reopen_values = _values(reopen, key_fields, value_fields)
    if not primary_values or not reopen_values:
        cross_status = "role-overlap-incomplete"
    elif primary_values == reopen_values:
        cross_status = "comparable-byte-identical"
    else:
        cross_status = "contradictory-values"
    if before_values and reopen_values:
        before_after = "unchanged" if before_values == reopen_values else "value-changed"
    else:
        before_after = "not-comparable"
    return {
        "primary_vs_reopen_status": cross_status,
        "before_vs_reopen_status": before_after,
        "before": _metadata(before, (*key_fields, *value_fields)),
        "primary_post_save": _metadata(primary, (*key_fields, *value_fields)),
        "reopen": _metadata(reopen, (*key_fields, *value_fields)),
    }


def _cycle_family_comparison(
    a_state: Mapping[str, Any],
    b_state: Mapping[str, Any],
    c_state: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "grouped_onArI_serial_3_type_0": _three_family_status(
            _serial_three_type_zero(a_state["on_ari"]),
            _serial_three_type_zero(b_state["on_ari"]),
            _serial_three_type_zero(c_state["on_ari"]),
            key_fields=("mid", "type", "using", "serial"),
            value_fields=_ON_ARI_VALUE_FIELDS,
        ),
        "request_associated_onMI": _three_family_status(
            _request_on_mi(a_state["on_mi"]),
            _request_on_mi(b_state["on_mi"]),
            _request_on_mi(c_state["on_mi"]),
            key_fields=("association",),
            value_fields=_ON_MI_VALUE_FIELDS,
        ),
        "AreaSet_vw": _three_family_status(
            _type_selected(a_state["area_set"], "vw"),
            _type_selected(b_state["area_set"], "vw"),
            _type_selected(c_state["area_set"], "vw"),
            key_fields=("mid", "aid", "type"),
            value_fields=_AREA_VALUE_FIELDS,
        ),
        "mid": _three_mid_status(a_state, b_state, c_state),
        "SpecialContour": _three_family_status(
            a_state["special_contour"],
            b_state["special_contour"],
            c_state["special_contour"],
            key_fields=("command", "direction", "source_path"),
            value_fields=_SPECIAL_VALUE_FIELDS,
        ),
    }


def _three_family_status(
    a_items: Sequence[Mapping[str, Any]],
    b_items: Sequence[Mapping[str, Any]],
    c_items: Sequence[Mapping[str, Any]],
    *,
    key_fields: Sequence[str],
    value_fields: Sequence[str],
) -> dict[str, Any]:
    values = [
        _values(items, key_fields, value_fields)
        for items in (a_items, b_items, c_items)
    ]
    status = (
        "byte-identical-through-cycle"
        if all(values) and values[0] == values[1] == values[2]
        else "not-comparable"
        if not all(values)
        else "value-changed"
    )
    return {
        "status": status,
        "A": _metadata(a_items, (*key_fields, *value_fields)),
        "B": _metadata(b_items, (*key_fields, *value_fields)),
        "C": _metadata(c_items, (*key_fields, *value_fields)),
        "semantic_mapping": False,
    }


def _three_mid_status(*states: Mapping[str, Any]) -> dict[str, Any]:
    mids = [_snapshot_mids(state) for state in states]
    return {
        "status": (
            "byte-identical-through-cycle"
            if all(mids) and mids[0] == mids[1] == mids[2]
            else "not-comparable"
            if not all(mids)
            else "value-changed"
        ),
        "A": sorted(mids[0]),
        "B": sorted(mids[1]),
        "C": sorted(mids[2]),
    }


def _snapshot_mids(state: Mapping[str, Any]) -> set[str]:
    return {
        str(item["mid"])
        for family in ("on_mi", "area_set", "on_ari")
        for item in state[family]
        if item.get("mid") is not None
    }


def _area_state(
    artifact: VerifiedPhase2Artifact,
    windows: Sequence[str],
) -> dict[str, Any]:
    selected = set(windows)
    variants: dict[tuple[bytes, int], list[str]] = {}
    for record in artifact.records:
        if (
            record.window not in selected
            or record.command != "getAreaSet"
            or record.direction != "response"
        ):
            continue
        data = _record_data(record)
        if data.get("type") != "ar":
            continue
        raw = _segment(record, "$.body.data.subsets").raw
        info_size = _segment_int(
            record,
            "$.body.data.infoSize",
            data.get("infoSize"),
        )
        variants.setdefault((raw, info_size), []).append(record.window)
    if len(variants) != 1:
        return {
            "status": "missing" if not variants else "unstable",
            "variant_count": len(variants),
        }
    (raw, info_size), occurrences = next(iter(variants.items()))
    decoded: bytes | None = None
    base64_status = "strict-base64-round-trip-proven"
    try:
        decoded = decode_strict_base64_representation(raw.decode("ascii"))
    except (UnicodeDecodeError, RepresentationDecodeError):
        base64_status = "not-strict-canonical-base64"
    return {
        "status": "stable",
        "infoSize": info_size,
        "representation": {
            "length": len(raw),
            "sha256": sha256(raw).hexdigest(),
        },
        "strict_base64_derived": {
            "status": base64_status,
            "length": len(decoded) if decoded is not None else None,
            "sha256": sha256(decoded).hexdigest() if decoded is not None else None,
        },
        "occurrence_count": len(occurrences),
        "windows": sorted(set(occurrences)),
    }


def _stable_area_across_post_windows(
    artifact: VerifiedPhase2Artifact,
    *,
    primary_windows: Sequence[str],
    reopen_window: str,
) -> dict[str, Any]:
    primary = _area_state(artifact, primary_windows)
    reopen = _area_state(artifact, (reopen_window,))
    if primary.get("status") != "stable" or reopen.get("status") != "stable":
        return {
            "status": "missing-or-unstable-post-window",
            "primary_post_save": primary,
            "reopen": reopen,
        }
    comparison_fields = ("infoSize", "representation", "strict_base64_derived")
    if any(primary.get(field) != reopen.get(field) for field in comparison_fields):
        return {
            "status": "post-window-values-differ",
            "primary_post_save": primary,
            "reopen": reopen,
        }
    return {
        **primary,
        "occurrence_count": (
            int(primary["occurrence_count"]) + int(reopen["occurrence_count"])
        ),
        "windows": sorted({*primary["windows"], *reopen["windows"]}),
        "primary_post_save": primary,
        "reopen": reopen,
    }


def _three_state_area_analysis(
    a_state: Mapping[str, Any],
    b_state: Mapping[str, Any],
    c_state: Mapping[str, Any],
) -> dict[str, Any]:
    if any(state.get("status") != "stable" for state in (a_state, b_state, c_state)):
        classification = "not-comparable"
    else:
        digests = [state["representation"]["sha256"] for state in (a_state, b_state, c_state)]
        if digests[0] == digests[2] != digests[1]:
            classification = "byte-restored"
        elif digests[1] == digests[2] != digests[0]:
            classification = "persistent-rename-state"
        elif len(set(digests)) == 3:
            classification = "stable-third-encoding"
        else:
            classification = "unclassified-equality-pattern"
    return {
        "classification": classification,
        "A_pre_P2_11_original_name_state": dict(a_state),
        "B_P2_11_temp2_state": dict(b_state),
        "C_P2_12_restored_name_state": dict(c_state),
        "comparison_layers": [
            "original-representation-bytes",
            "strict-base64-derived-bytes",
            "length",
            "sha256",
            "infoSize",
        ],
        "semantic_mapping": False,
    }


def _restore_write_shape_comparison(  # noqa: PLR0913
    current: VerifiedPhase2Artifact,
    p2_11: VerifiedPhase2Artifact,
    divide_artifact_dir: Path,
    *,
    expected_divide_capture_id: str,
    authoritative_command: Any,
    restore_windows: set[str],
) -> dict[str, Any]:
    if authoritative_command != "setAreaSet":
        return {"status": "not-applicable", "reason": "write-is-not-setAreaSet"}
    divide = _verified_artifact(divide_artifact_dir)
    if divide.capture_id != expected_divide_capture_id:
        raise AreaRenameRestoreReferenceError("Divide request-shape capture mismatch")
    restore = _request_records(current, restore_windows)
    rename = _request_records(p2_11, None)
    divided = _request_records(divide, None)
    if any(len(records) != 1 for records in (restore, rename, divided)):
        return {
            "status": "not-comparable",
            "restore_count": len(restore),
            "rename_count": len(rename),
            "divide_count": len(divided),
        }
    return {
        "status": "comparable",
        "restore": _verified_record_shape(restore[0]),
        "P2_11_rename": _verified_record_shape(rename[0]),
        "P2_09c_divide": _verified_record_shape(divided[0]),
        "semantic_mapping": False,
    }


def _request_records(
    artifact: VerifiedPhase2Artifact,
    windows: set[str] | None,
) -> list[Any]:
    return [
        record
        for record in artifact.records
        if record.command == "setAreaSet"
        and record.direction == "request"
        and (windows is None or record.window in windows)
    ]


def _all_expected(
    items: Sequence[Mapping[str, Any]],
    expected: Mapping[str, Any],
) -> bool:
    return bool(items) and all(
        all(item.get(key) == value for key, value in expected.items()) for item in items
    )


def _values(
    items: Sequence[Mapping[str, Any]],
    key_fields: Sequence[str],
    value_fields: Sequence[str],
) -> set[tuple[Any, ...]]:
    fields = (*key_fields, *value_fields)
    return {tuple(item.get(field) for field in fields) for item in items}


def _metadata(
    items: Sequence[Mapping[str, Any]],
    fields: Sequence[str],
) -> list[dict[str, Any]]:
    values = {
        tuple((field, item.get(field)) for field in fields)
        for item in items
    }
    return [dict(value) for value in sorted(values, key=repr)]


def _on_mi_role_inventory(items: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return _metadata(
        items,
        ("association", "original_length", "original_sha256", "info_size"),
    )


def _on_ari_role_inventory(items: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return _metadata(
        items,
        ("serial", "type", "derived_length", "derived_sha256", "info_size"),
    )
