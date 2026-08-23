"""Fail-closed reference and result helpers for controlled Area rename research."""

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
from .goat_map_delta import (
    ArtifactDeltaError,
    VerifiedArtifactRecord,
    load_verified_phase2_artifact,
)

if TYPE_CHECKING:
    from pathlib import Path

    from .goat_map_area_split import AreaSplitEvidenceObserver

_REFERENCE_CAPTURE_ID = "fad46b96aab44781881ce37b230ecf39"
_DIVIDE_CAPTURE_ID = "212a37d365b54f77bbb6c0424ff94246"
_AREA_VALUE_FIELDS = ("info_size", "subsets_length", "subsets_sha256")
_ON_MI_VALUE_FIELDS = (
    "mid",
    "info_size",
    "original_length",
    "original_sha256",
    "derived_length",
    "derived_sha256",
    "context_signature_hex",
    "observed_context_class",
    "opaque_remainder_length",
    "opaque_remainder_sha256",
)
_ON_ARI_VALUE_FIELDS = (
    "info_size",
    "derived_length",
    "derived_sha256",
    "context_signature_hex",
    "opaque_common_body_region_length",
    "opaque_common_body_region_sha256",
    "opaque_after_701_length",
    "opaque_after_701_sha256",
)
_EXPECTED_AREA_AR = {
    "mid": "1",
    "aid": "0",
    "type": "ar",
    "info_size": 281,
    "subsets_length": 116,
    "subsets_sha256": "3ea94e0f116c4acacd1c7d64fbe6caa98c5fea82348cd3ccdef5c7aba0ada57a",
}
_EXPECTED_ON_ARI = {
    "mid": "1",
    "type": "0",
    "serial": 3,
    "info_size": 6933,
    "derived_length": 1651,
    "derived_sha256": "46a2843dcc5595a83d68c378cd51c534d8310315db0967fc016d0647dc9a8c97",
    "context_signature_hex": "c8c9b157b2874a80dcc06c3923718e503b",
}


class AreaRenameReferenceError(ValueError):
    """The immutable post-Merge or Divide reference cannot be used safely."""


@dataclass(frozen=True, slots=True)
class AreaRenameReference:
    """Verified structural post-Merge C-state used by the rename gate."""

    capture_id: str
    phase: str
    c_state: dict[str, Any]


def load_area_rename_reference(
    artifact_dir: Path,
    *,
    expected_capture_id: str = _REFERENCE_CAPTURE_ID,
) -> AreaRenameReference:
    """Verify P2-10d and require its two app-init rounds to be byte-stable."""
    try:
        artifact = load_verified_phase2_artifact(artifact_dir)
    except ArtifactDeltaError as err:
        raise AreaRenameReferenceError(str(err)) from err
    if artifact.capture_id != expected_capture_id:
        raise AreaRenameReferenceError("Area rename C-state capture ID mismatch")
    first = _artifact_snapshot(
        artifact,
        (f"{artifact.phase}:post-merge-app-init-1",),
    )
    second = _artifact_snapshot(
        artifact,
        (f"{artifact.phase}:post-merge-app-init-2",),
    )
    checks = _snapshot_checks(first, second, second)
    if any(item["status"] != "passed" for item in checks.values()):
        raise AreaRenameReferenceError("P2-10d C-state is not stable in both rounds")
    _validate_expected_c_state(second)
    return AreaRenameReference(
        capture_id=artifact.capture_id,
        phase=artifact.phase,
        c_state=second,
    )


def evaluate_area_rename_preconditions(  # noqa: PLR0913
    base: Mapping[str, Any],
    evidence: AreaSplitEvidenceObserver,
    *,
    init_1_window: str,
    init_2_window: str,
    reference: AreaRenameReference,
    capture_records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Require two exact reproductions of the approved post-Merge C-state."""
    result = cast("dict[str, Any]", orjson.loads(orjson.dumps(base)))
    failures = list(result["failures"])
    first = _observer_snapshot(evidence, (init_1_window,))
    second = _observer_snapshot(evidence, (init_2_window,))
    first["special_contour"] = _capture_special_snapshot(
        capture_records,
        (init_1_window,),
    )
    second["special_contour"] = _capture_special_snapshot(
        capture_records,
        (init_2_window,),
    )
    checks = _snapshot_checks(first, second, reference.c_state)
    for name, check in checks.items():
        if check["status"] != "passed":
            failures.append(
                {
                    "check": f"p2-10d-c-state-{name}",
                    "reason": check["reason"],
                }
            )
    passed = not failures
    result["checks"]["p2_10d_c_state"] = checks
    result["status"] = "passed" if passed else "inconclusive"
    result["result"] = "precondition-passed" if passed else "precondition-failed"
    result["split_edit_gate_open"] = False
    result["rename_edit_gate_open"] = passed
    result["failures"] = failures
    result["reference"] = {
        "capture_id": reference.capture_id,
        "phase": reference.phase,
        "artifact_verified": True,
        "artifact_modified": False,
    }
    return result


def add_area_rename_analysis(  # noqa: PLR0913
    report: dict[str, Any],
    evidence: AreaSplitEvidenceObserver,
    *,
    before_window: str,
    primary_post_windows: Sequence[str],
    reopen_window: str,
    capture_records: Sequence[Mapping[str, Any]],
    divide_reference_artifact: Path,
    expected_divide_capture_id: str = _DIVIDE_CAPTURE_ID,
) -> None:
    """Add post stability, interpretation guard, and optional write-shape comparison."""
    controlled = report["controlled_area_rename"]
    before = _observer_snapshot(evidence, (before_window,))
    primary = _observer_snapshot(evidence, primary_post_windows)
    reopened = _observer_snapshot(evidence, (reopen_window,))
    for snapshot, windows in (
        (before, (before_window,)),
        (primary, primary_post_windows),
        (reopened, (reopen_window,)),
    ):
        snapshot["special_contour"] = _capture_special_snapshot(
            capture_records,
            windows,
        )
    stability_checks = _snapshot_checks(primary, reopened, primary)
    post_stable = all(item["status"] == "passed" for item in stability_checks.values())
    comparison = controlled.get("comparison") or {}
    area_status = _selected_group_status(
        comparison.get("getAreaSet"),
        {"mid": "1", "aid": "0", "type": "ar"},
    )
    on_ari_status = _selected_group_status(
        comparison.get("grouped_onArI"),
        {"mid": "1", "type": "0", "serial": 3},
    )
    result_class = _rename_result_class(area_status, on_ari_status)
    write = controlled.get("write_attribution") or {}
    shape = _set_area_set_shape_comparison(
        divide_reference_artifact,
        expected_capture_id=expected_divide_capture_id,
        capture_records=capture_records,
        rename_windows={
            controlled["windows"].get("rename_edit"),
            controlled["windows"].get("rename_save"),
        },
        authoritative_command=write.get("authoritative_command"),
    )
    controlled["rename_analysis"] = {
        "analysis_version": "goat-controlled-area-rename/v1",
        "post_state_stability": {
            "status": "passed" if post_stable else "inconclusive",
            "primary_windows": list(primary_post_windows),
            "reopen_window": reopen_window,
            "checks": stability_checks,
        },
        "selected_deltas": {
            "AreaSet_ar": area_status,
            "grouped_onArI_serial_3_type_0": on_ari_status,
        },
        "result_classification": result_class,
        "interpretation": {
            "rename_or_metadata_edit_association_only": True,
            "name_bytes_located_in_structure": False,
            "general_save_or_edit_generation_remains_alternative": True,
            "no_op_save_control_performed": False,
        },
        "setAreaSet_request_shape_vs_divide": shape,
        "inverse_control": "rename-back-must-use-a-separate-capture-if-needed",
        "semantic_parser": False,
        "geometry_interpretation": False,
    }
    if not post_stable or result_class == "not-comparable":
        controlled["experiment_status"] = "inconclusive"
        controlled["delta_status"] = "inconclusive"
        controlled["status"] = "inconclusive"


def _snapshot_checks(
    first: Mapping[str, Any],
    second: Mapping[str, Any],
    reference: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    return {
        "request_associated_onMI": _exact_check(
            _request_on_mi(first["on_mi"]),
            _request_on_mi(second["on_mi"]),
            _request_on_mi(reference["on_mi"]),
            key_fields=("association",),
            value_fields=_ON_MI_VALUE_FIELDS,
        ),
        "AreaSet_ar": _exact_check(
            _type_selected(first["area_set"], "ar"),
            _type_selected(second["area_set"], "ar"),
            _type_selected(reference["area_set"], "ar"),
            key_fields=("mid", "aid", "type"),
            value_fields=_AREA_VALUE_FIELDS,
        ),
        "AreaSet_vw": _exact_check(
            _type_selected(first["area_set"], "vw"),
            _type_selected(second["area_set"], "vw"),
            _type_selected(reference["area_set"], "vw"),
            key_fields=("mid", "aid", "type"),
            value_fields=_AREA_VALUE_FIELDS,
        ),
        "grouped_onArI_serial_3_type_0": _exact_check(
            _serial_three_type_zero(first["on_ari"]),
            _serial_three_type_zero(second["on_ari"]),
            _serial_three_type_zero(reference["on_ari"]),
            key_fields=("mid", "type", "using", "serial"),
            value_fields=_ON_ARI_VALUE_FIELDS,
        ),
        "SpecialContour": _exact_check(
            first["special_contour"],
            second["special_contour"],
            reference["special_contour"],
            key_fields=("command", "direction", "source_path"),
            value_fields=("byte_length", "sha256"),
        ),
    }


def _exact_check(
    first: Sequence[Mapping[str, Any]],
    second: Sequence[Mapping[str, Any]],
    reference: Sequence[Mapping[str, Any]],
    *,
    key_fields: Sequence[str],
    value_fields: Sequence[str],
) -> dict[str, Any]:
    first_values = _value_set(first, key_fields, value_fields)
    second_values = _value_set(second, key_fields, value_fields)
    reference_values = _value_set(reference, key_fields, value_fields)
    if not first_values or not second_values or not reference_values:
        return {"status": "failed", "reason": "missing-comparable-values"}
    if first_values != second_values:
        return {"status": "failed", "reason": "two-readback-values-differ"}
    if first_values != reference_values:
        return {"status": "failed", "reason": "current-state-does-not-match-p2-10d-c"}
    return {
        "status": "passed",
        "reason": None,
        "variant_count": len(first_values),
    }


def _value_set(
    items: Sequence[Mapping[str, Any]],
    key_fields: Sequence[str],
    value_fields: Sequence[str],
) -> set[tuple[Any, ...]]:
    fields = (*key_fields, *value_fields)
    return {tuple(item.get(field) for field in fields) for item in items}


def _validate_expected_c_state(snapshot: Mapping[str, Any]) -> None:
    area = _type_selected(snapshot["area_set"], "ar")
    on_ari = _serial_three_type_zero(snapshot["on_ari"])
    if not any(_matches(item, _EXPECTED_AREA_AR) for item in area):
        raise AreaRenameReferenceError("P2-10d AreaSet ar target mismatch")
    if not any(_matches(item, _EXPECTED_ON_ARI) for item in on_ari):
        raise AreaRenameReferenceError("P2-10d grouped onArI target mismatch")


def _matches(item: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    return all(item.get(key) == value for key, value in expected.items())


def _selected_group_status(
    comparison: Mapping[str, Any] | None,
    expected_key: Mapping[str, Any],
) -> str:
    if not comparison:
        return "not-comparable"
    matches = [
        item
        for item in comparison.get("groups", [])
        if all(item.get("key", {}).get(key) == value for key, value in expected_key.items())
    ]
    return matches[0]["status"] if len(matches) == 1 else "not-comparable"


def _rename_result_class(area_status: str, on_ari_status: str) -> str:
    unchanged = {"unchanged", "occurrence-count-changed"}
    if area_status in unchanged and on_ari_status in unchanged:
        return "byte-identical-static-families"
    if area_status == "value-changed" and on_ari_status in unchanged:
        return "rename-associated-AreaSet-only-structural-change"
    if area_status in unchanged and on_ari_status == "value-changed":
        return "rename-associated-onArI-only-structural-change"
    if area_status == "value-changed" and on_ari_status == "value-changed":
        return "rename-associated-metadata-edit-associated-structural-change"
    return "not-comparable"


def _set_area_set_shape_comparison(
    divide_artifact: Path,
    *,
    expected_capture_id: str,
    capture_records: Sequence[Mapping[str, Any]],
    rename_windows: set[str | None],
    authoritative_command: str | None,
) -> dict[str, Any]:
    if authoritative_command != "setAreaSet":
        return {
            "status": "not-applicable",
            "reason": "authoritative-write-is-not-setAreaSet",
        }
    try:
        reference = load_verified_phase2_artifact(divide_artifact)
    except ArtifactDeltaError as err:
        raise AreaRenameReferenceError(str(err)) from err
    if reference.capture_id != expected_capture_id:
        raise AreaRenameReferenceError("Divide write reference capture ID mismatch")
    reference_records = [
        item
        for item in reference.records
        if item.command == "setAreaSet" and item.direction == "request"
    ]
    current_records = [
        item
        for item in capture_records
        if item.get("window") in rename_windows
        and item.get("command") == "setAreaSet"
        and item.get("direction") == "request"
    ]
    if len(reference_records) != 1 or len(current_records) != 1:
        return {
            "status": "not-comparable",
            "reference_request_count": len(reference_records),
            "rename_request_count": len(current_records),
        }
    before = _verified_record_shape(reference_records[0])
    after = _captured_record_shape(current_records[0])
    return {
        "status": "identical-shape" if before == after else "shape-changed",
        "divide": before,
        "rename": after,
        "semantic_field_interpretation": False,
    }


def _verified_record_shape(record: VerifiedArtifactRecord) -> dict[str, Any]:
    return {
        "envelope": _value_shape(record.sanitized_envelope),
        "opaque_segments": sorted(
            {
                (
                    item.source_path,
                    item.kind,
                    len(item.raw),
                )
                for item in record.opaque_segments
            }
        ),
    }


def _captured_record_shape(record: Mapping[str, Any]) -> dict[str, Any]:
    segments = []
    for item in record.get("opaque_segments", []):
        original = item.get("representations", {}).get("original")
        if isinstance(original, Mapping):
            segments.append(
                (
                    item.get("source_path"),
                    original.get("kind"),
                    original.get("byte_length"),
                )
            )
    return {
        "envelope": _value_shape(record.get("sanitized_envelope")),
        "opaque_segments": sorted(set(segments), key=repr),
    }


def _value_shape(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _value_shape(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [_value_shape(item) for item in value]
    return type(value).__name__
