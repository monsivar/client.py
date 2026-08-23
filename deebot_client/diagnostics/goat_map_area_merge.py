"""Read-only reference checks for the controlled GOAT Area merge inverse test."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import TYPE_CHECKING, Any, cast

import orjson

from .goat_map_delta import (
    ArtifactDeltaError,
    VerifiedArtifactRecord,
    load_verified_phase2_artifact,
)
from .goat_map_inner_structure_view import recognize_inner_structure
from .goat_map_on_ari_framing import collect_grouped_on_ari_observations
from .goat_map_representation import preserve_onmi_info_representation
from .goat_map_structural_header import recognize_structural_header

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from .goat_map_area_split import AreaSplitEvidenceObserver

_REFERENCE_CAPTURE_ID = "212a37d365b54f77bbb6c0424ff94246"
_ORIGINAL_AREA_AR = {
    "mid": "1",
    "aid": "0",
    "type": "ar",
    "info_size": 291,
    "subsets_length": 124,
    "subsets_sha256": "72ebe704cb5890adb28ec1be05c228a6ef9addff0738df811808f671e0afd855",
}
_ORIGINAL_ON_ARI = {
    "mid": "1",
    "type": "0",
    "serial": 3,
    "info_size": 6933,
    "derived_length": 1651,
    "derived_sha256": "aabdcb55ae2bcea24fe18eb0c37f27cbe99bcfb9a71fd30b7a147aeb99978b4c",
    "context_signature_hex": "b4fc81d4375de7a0f636f001dc016fe0ca",
}
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


class AreaMergeReferenceError(ValueError):
    """The immutable P2-09c reference is missing or does not match approval."""


@dataclass(frozen=True, slots=True)
class AreaMergeReference:
    """Sanitized structural snapshots derived from the immutable P2-09c artifact."""

    capture_id: str
    phase: str
    original_pre_split: dict[str, Any]
    split_post: dict[str, Any]


def load_area_merge_reference(
    artifact_dir: Path,
    *,
    expected_capture_id: str = _REFERENCE_CAPTURE_ID,
) -> AreaMergeReference:
    """Verify P2-09c and derive the two reference states without modifying it."""
    try:
        artifact = load_verified_phase2_artifact(artifact_dir)
    except ArtifactDeltaError as err:
        raise AreaMergeReferenceError(str(err)) from err
    if artifact.capture_id != expected_capture_id:
        raise AreaMergeReferenceError("Area merge reference capture ID mismatch")
    pre_window = f"{artifact.phase}:pre-split-app-init-2"
    reopen_window = f"{artifact.phase}:post-split-reopen"
    post_window = (
        reopen_window
        if any(record.window == reopen_window for record in artifact.records)
        else f"{artifact.phase}:post-split-readback"
    )
    original = _artifact_snapshot(artifact, (pre_window,))
    split_post = _artifact_snapshot(artifact, (post_window,))
    _validate_approved_original(original)
    if not split_post["area_set"] or not split_post["on_ari"]:
        raise AreaMergeReferenceError("P2-09c split-state reference is incomplete")
    return AreaMergeReference(
        capture_id=artifact.capture_id,
        phase=artifact.phase,
        original_pre_split=original,
        split_post=split_post,
    )


def load_pre_merge_reference(
    artifact_dir: Path,
    *,
    expected_capture_id: str,
) -> dict[str, Any]:
    """Verify the immutable P2-10 pre-merge abort and its stable split state."""
    try:
        artifact = load_verified_phase2_artifact(artifact_dir)
    except ArtifactDeltaError as err:
        raise AreaMergeReferenceError(str(err)) from err
    if artifact.capture_id != expected_capture_id:
        raise AreaMergeReferenceError("Pre-merge reference capture ID mismatch")
    first = _artifact_snapshot(
        artifact,
        (f"{artifact.phase}:pre-merge-app-init-1",),
    )
    second = _artifact_snapshot(
        artifact,
        (f"{artifact.phase}:pre-merge-app-init-2",),
    )
    checks = (
        _reference_value_check(
            first["area_set"],
            second["area_set"],
            first["area_set"],
            key_fields=("mid", "aid", "type"),
            value_fields=("info_size", "subsets_length", "subsets_sha256"),
        ),
        _reference_value_check(
            _request_on_mi(first["on_mi"]),
            _request_on_mi(second["on_mi"]),
            _request_on_mi(first["on_mi"]),
            key_fields=("association",),
            value_fields=_ON_MI_VALUE_FIELDS,
        ),
        _reference_value_check(
            _serial_three_type_zero(first["on_ari"]),
            _serial_three_type_zero(second["on_ari"]),
            _serial_three_type_zero(first["on_ari"]),
            key_fields=("mid", "type", "using", "serial"),
            value_fields=_ON_ARI_VALUE_FIELDS,
        ),
    )
    if any(check["status"] != "passed" for check in checks):
        raise AreaMergeReferenceError("Pre-merge reference split state is not stable")
    return {
        "capture_id": artifact.capture_id,
        "phase": artifact.phase,
        "split_state": second,
        "artifact_modified": False,
    }


def analyze_area_merge_recovery_artifact(  # noqa: PLR0913
    recovery_artifact_dir: Path,
    *,
    original_artifact_dir: Path,
    pre_merge_artifact_dir: Path,
    expected_original_capture_id: str,
    expected_pre_merge_capture_id: str,
    recovery_precondition_status: str = "unknown",
    unexpected_control_sequences: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Compare a passive post-merge recovery against both immutable references."""
    original = load_area_merge_reference(
        original_artifact_dir,
        expected_capture_id=expected_original_capture_id,
    )
    pre_merge = load_pre_merge_reference(
        pre_merge_artifact_dir,
        expected_capture_id=expected_pre_merge_capture_id,
    )
    try:
        recovery = load_verified_phase2_artifact(recovery_artifact_dir)
    except ArtifactDeltaError as err:
        raise AreaMergeReferenceError(str(err)) from err
    first = _artifact_snapshot(
        recovery,
        (f"{recovery.phase}:post-merge-app-init-1",),
    )
    second = _artifact_snapshot(
        recovery,
        (f"{recovery.phase}:post-merge-app-init-2",),
    )
    stability = _snapshot_stability(first, second)
    post = _combine_snapshots(first, second)
    original_on_ari_targets = _serial_three_type_zero(
        original.original_pre_split["on_ari"]
    )
    if len(original_on_ari_targets) != 1:
        raise AreaMergeReferenceError(
            "P2-09c original grouped onArI restoration target is ambiguous"
        )
    area_ar = _target_assessment(
        post["area_set"],
        _ORIGINAL_AREA_AR,
        key_fields=("mid", "aid", "type"),
        value_fields=("info_size", "subsets_length", "subsets_sha256"),
    )
    on_ari = _target_assessment(
        post["on_ari"],
        original_on_ari_targets[0],
        key_fields=("mid", "type", "serial"),
        value_fields=_ON_ARI_VALUE_FIELDS,
    )
    exact_restoration = (
        area_ar["status"] == "exact-match-observed"
        and on_ari["status"] == "exact-match-observed"
    )
    classification = classify_area_merge_recovery(
        post_merge_stability_status=stability["status"],
        recovery_precondition_status=recovery_precondition_status,
        exact_restoration=exact_restoration,
        area_state_stable=area_ar["post_state_stable_across_windows"],
        on_ari_state_stable=on_ari["post_state_stable_across_windows"],
    )
    source_isolation_passed = recovery_precondition_status == "passed"
    confounders: list[dict[str, Any]] = [
        {
            "kind": "capture-finalization-failure",
            "effect": (
                "the Merge network-write and immediate post-save traffic were "
                "not persisted; the post state is recovered in a later passive run"
            ),
        }
    ]
    if not source_isolation_passed:
        confounders.append(
            {
                "kind": "controlled-source-isolation-failed",
                "effect": "strict recovery attribution remains inconclusive",
                "unexpected_sequences": [dict(item) for item in unexpected_control_sequences],
            }
        )
    return {
        "analysis_version": "goat-area-merge-recovery/v1",
        "analysis_kind": "read-only-cross-artifact-inverse-comparison",
        "artifact_modification": False,
        "experiment_status": classification["experiment_status"],
        "delta_status": classification["delta_status"],
        "write_attribution": {
            "status": "unavailable-capture-finalization-failed",
            "authoritative_network_timestamp": None,
            "authoritative_command": None,
        },
        "references": {
            "original_pre_split_capture_id": original.capture_id,
            "pre_merge_split_capture_id": pre_merge["capture_id"],
            "post_merge_recovery_capture_id": recovery.capture_id,
        },
        "post_merge_stability": stability,
        "controlled_source_isolation": {
            "status": "passed" if source_isolation_passed else "failed",
            "recovery_precondition_status": recovery_precondition_status,
            "unexpected_sequences": [dict(item) for item in unexpected_control_sequences],
        },
        "within_run_inverse_delta": _snapshot_delta(
            pre_merge["split_state"],
            post,
        ),
        "cross_experiment_restoration": {
            "status": classification["restoration_status"],
            "area_set_ar": area_ar,
            "on_ari_serial_3_type_0": on_ari,
            "request_associated_onMI": _invariant_assessment(
                _request_on_mi(original.original_pre_split["on_mi"]),
                _request_on_mi(post["on_mi"]),
                key_fields=("association",),
                value_fields=_ON_MI_VALUE_FIELDS,
            ),
            "area_set_vw": _invariant_assessment(
                _type_selected(original.original_pre_split["area_set"], "vw"),
                _type_selected(post["area_set"], "vw"),
                key_fields=("mid", "aid", "type"),
                value_fields=("info_size", "subsets_length", "subsets_sha256"),
            ),
            "SpecialContour": _invariant_assessment(
                original.original_pre_split["special_contour"],
                post["special_contour"],
                key_fields=("command", "direction", "source_path"),
                value_fields=("byte_length", "sha256"),
            ),
        },
        "confounders": confounders,
        "semantic_parser": False,
        "geometry_interpretation": False,
    }


def classify_area_merge_recovery(
    *,
    post_merge_stability_status: str,
    recovery_precondition_status: str,
    exact_restoration: bool,
    area_state_stable: bool,
    on_ari_state_stable: bool,
) -> dict[str, str]:
    """Keep structural stability, attribution, and restoration statuses separate."""
    source_isolation_passed = recovery_precondition_status == "passed"
    structurally_complete = post_merge_stability_status == "passed"
    return {
        "experiment_status": (
            "completed-action-with-recovered-post-readback"
            if source_isolation_passed
            else "recovery-readback-inconclusive"
        ),
        "delta_status": (
            "recovered-controlled-structural-evidence"
            if structurally_complete and source_isolation_passed
            else "inconclusive"
        ),
        "restoration_status": (
            "restored-byte-for-byte"
            if exact_restoration
            else "stable-third-encoding"
            if area_state_stable and on_ari_state_stable
            else "not-restored-or-not-yet-stable"
        ),
    }


def evaluate_area_merge_preconditions(
    base: Mapping[str, Any],
    evidence: AreaSplitEvidenceObserver,
    *,
    init_1_window: str,
    init_2_window: str,
    reference: AreaMergeReference,
) -> dict[str, Any]:
    """Require two stable split-state readbacks before opening the Merge gate."""
    result = cast("dict[str, Any]", orjson.loads(orjson.dumps(base)))
    failures = list(result["failures"])
    first = _observer_snapshot(evidence, (init_1_window,))
    second = _observer_snapshot(evidence, (init_2_window,))

    split_area_check = _reference_value_check(
        first["area_set"],
        second["area_set"],
        reference.split_post["area_set"],
        key_fields=("mid", "aid", "type"),
        value_fields=("info_size", "subsets_length", "subsets_sha256"),
    )
    if split_area_check["status"] != "passed":
        failures.append(
            {
                "check": "p2-09c-split-state-getAreaSet",
                "reason": split_area_check["reason"],
            }
        )

    split_on_mi_check = _reference_value_check(
        _request_on_mi(first["on_mi"]),
        _request_on_mi(second["on_mi"]),
        _request_on_mi(reference.split_post["on_mi"]),
        key_fields=("association",),
        value_fields=("mid", "info_size", "original_length", "original_sha256"),
    )
    if split_on_mi_check["status"] != "passed":
        failures.append(
            {
                "check": "p2-09c-split-state-onMI",
                "reason": split_on_mi_check["reason"],
            }
        )

    direct_first = _serial_three_type_zero(first["on_ari"])
    direct_second = _serial_three_type_zero(second["on_ari"])
    direct_reference = _serial_three_type_zero(reference.split_post["on_ari"])
    direct_check = _optional_direct_group_check(
        direct_first,
        direct_second,
        direct_reference,
    )
    if direct_check["status"] == "failed":
        failures.append(
            {
                "check": "repeatable-serial-3-type-0-split-state",
                "reason": direct_check["reason"],
            }
        )

    result["checks"]["p2_09c_split_state_getAreaSet"] = split_area_check
    result["checks"]["p2_09c_split_state_onMI"] = split_on_mi_check
    result["checks"]["serial_3_type_0_repeatability"] = direct_check
    passed = not failures
    result["status"] = "passed" if passed else "inconclusive"
    result["result"] = "precondition-passed" if passed else "precondition-failed"
    result["split_edit_gate_open"] = False
    result["merge_edit_gate_open"] = passed
    result["failures"] = failures
    result["reference"] = {
        "capture_id": reference.capture_id,
        "phase": reference.phase,
        "artifact_verified": True,
        "artifact_modified": False,
    }
    return result


def add_area_merge_restoration_analysis(
    report: dict[str, Any],
    evidence: AreaSplitEvidenceObserver,
    *,
    reference: AreaMergeReference,
    post_merge_windows: Sequence[str],
    capture_records: Sequence[Mapping[str, Any]],
) -> None:
    """Add inverse and restoration results without changing opaque observations."""
    controlled = report["controlled_area_merge"]
    after = _observer_snapshot(evidence, post_merge_windows)
    original = reference.original_pre_split

    area_ar = _target_assessment(
        after["area_set"],
        _ORIGINAL_AREA_AR,
        key_fields=("mid", "aid", "type"),
        value_fields=("info_size", "subsets_length", "subsets_sha256"),
    )
    original_on_ari_targets = _serial_three_type_zero(original["on_ari"])
    if len(original_on_ari_targets) != 1:
        raise AreaMergeReferenceError(
            "P2-09c original grouped onArI restoration target is ambiguous"
        )
    on_ari = _target_assessment(
        after["on_ari"],
        original_on_ari_targets[0],
        key_fields=("mid", "type", "serial"),
        value_fields=_ON_ARI_VALUE_FIELDS,
    )
    on_mi = _invariant_assessment(
        _request_on_mi(original["on_mi"]),
        _request_on_mi(after["on_mi"]),
        key_fields=("association",),
        value_fields=("mid", "info_size", "original_length", "original_sha256"),
    )
    area_vw = _invariant_assessment(
        _type_selected(original["area_set"], "vw"),
        _type_selected(after["area_set"], "vw"),
        key_fields=("mid", "aid", "type"),
        value_fields=("info_size", "subsets_length", "subsets_sha256"),
    )
    post_special = _capture_special_snapshot(capture_records, post_merge_windows)
    special_cross = _invariant_assessment(
        original["special_contour"],
        post_special,
        key_fields=("command", "direction", "source_path"),
        value_fields=("byte_length", "sha256"),
    )
    observed_mids = sorted(
        {item["mid"] for item in (*after["on_mi"], *after["area_set"], *after["on_ari"])}
    )
    special = controlled.get("comparison", {}).get("SpecialContour_control", {})
    special_statuses = special.get("statuses", {})
    special_unchanged = not any(
        special_statuses.get(name, 0)
        for name in ("value-changed", "before-only", "after-only")
    )

    exact = area_ar["status"] == "exact-match-observed" and on_ari[
        "status"
    ] == "exact-match-observed"
    stable_alternative = (
        not exact
        and area_ar["post_state_stable_across_windows"]
        and on_ari["post_state_stable_across_windows"]
    )
    restoration_status = (
        "restored-byte-for-byte"
        if exact
        else "stable-third-encoding"
        if stable_alternative
        else "not-restored-or-not-yet-stable"
    )
    controlled["within_run_inverse_delta"] = controlled.get("comparison")
    controlled["cross_experiment_restoration"] = {
        "status": restoration_status,
        "comparison": "p2-09c-original-pre-split-to-p2-10-post-merge",
        "reference_capture_id": reference.capture_id,
        "area_set_ar": area_ar,
        "on_ari_serial_3_type_0": on_ari,
        "invariants": {
            "request_associated_onMI": on_mi,
            "area_set_vw": area_vw,
            "mid": {
                "status": "unchanged" if observed_mids == ["1"] else "value-changed",
                "expected": ["1"],
                "observed": observed_mids,
            },
            "SpecialContour": {
                "status": special_cross["status"],
                "cross_experiment": special_cross,
                "within_run": special,
                "within_run_has_no_value_or_presence_change": special_unchanged,
            },
        },
        "exact_restoration_required_for_experiment_validity": False,
        "opaque_data_interpretation": False,
    }
    controlled["restoration_status"] = restoration_status
    controlled["reference_artifact"] = {
        "capture_id": reference.capture_id,
        "artifact_modified": False,
    }
    controlled["capture_record_count_used_for_comparison"] = len(capture_records)


def _artifact_snapshot(artifact: Any, windows: Sequence[str]) -> dict[str, Any]:
    selected = set(windows)
    records = [record for record in artifact.records if record.window in selected]
    on_mi = [_artifact_on_mi(item) for item in records if item.command == "onMI"]
    area_set = [
        _artifact_area_set(item)
        for item in records
        if item.command == "getAreaSet" and item.direction == "response"
    ]
    observations, _ = collect_grouped_on_ari_observations((artifact,))
    on_ari = [
        _group_metadata(item)
        for item in observations
        if selected.intersection(item.windows)
    ]
    special = [
        {
            "command": record.command,
            "direction": record.direction,
            "source_path": segment.source_path,
            "byte_length": len(segment.raw),
            "sha256": segment.sha256,
        }
        for record in records
        if record.command
        in {"getSpecialContour", "onSpecialContour", "setSpecialContour"}
        for segment in record.opaque_segments
    ]
    return {
        "on_mi": on_mi,
        "area_set": area_set,
        "on_ari": on_ari,
        "special_contour": special,
    }


def _artifact_on_mi(record: VerifiedArtifactRecord) -> dict[str, Any]:
    data = _record_data(record)
    info = _segment(record, "$.body.data.info").raw.decode("ascii")
    preserved = preserve_onmi_info_representation(info)
    info_size = _segment_int(record, "$.body.data.infoSize", data.get("infoSize"))
    header = recognize_structural_header(preserved.decoded, envelope_info_size=info_size)
    inner = recognize_inner_structure(header)
    association = (
        "request-associated"
        if len(info) == 876
        else "cadence-associated"
        if len(info) == 52
        else "unclassified"
    )
    return {
        "window": record.window,
        "association": association,
        "mid": str(data["mid"]),
        "info_size": info_size,
        "original_length": len(info),
        "original_sha256": preserved.original_sha256,
        "derived_length": len(preserved.decoded),
        "derived_sha256": preserved.decoded_sha256,
        "context_signature_hex": inner.context_signature_raw.hex(),
        "observed_context_class": inner.observed_context_class,
        "opaque_remainder_length": len(inner.remainder),
        "opaque_remainder_sha256": sha256(inner.remainder).hexdigest(),
    }


def _artifact_area_set(record: VerifiedArtifactRecord) -> dict[str, Any]:
    data = _record_data(record)
    raw = _segment(record, "$.body.data.subsets").raw
    return {
        "window": record.window,
        "mid": str(data["mid"]),
        "aid": _segment(record, "$.body.data.aid").raw.decode("utf-8"),
        "type": str(data["type"]),
        "info_size": _segment_int(record, "$.body.data.infoSize", data.get("infoSize")),
        "subsets_length": len(raw),
        "subsets_sha256": sha256(raw).hexdigest(),
    }


def _group_metadata(observation: Any) -> dict[str, Any]:
    assembled = observation.segment_set
    info_size = int(assembled.identity.info_size)
    header = recognize_structural_header(
        assembled.derived_concatenation,
        envelope_info_size=info_size,
    )
    inner = recognize_inner_structure(header, envelope_serial=assembled.identity.serial)
    common: bytes | None = None
    tail: bytes | None = None
    if (
        inner.observed_context_class == "observed-onArI-b4-signature"
        and len(inner.remainder) >= 668
    ):
        common = inner.remainder[:668]
        tail = inner.remainder[668:]
    return {
        "windows": list(observation.windows),
        "mid": str(assembled.identity.mid),
        "type": str(assembled.identity.type),
        "using": str(assembled.identity.using),
        "serial": assembled.identity.serial,
        "info_size": info_size,
        "derived_length": assembled.derived_concatenation_length,
        "derived_sha256": assembled.derived_concatenation_sha256,
        "context_signature_hex": inner.context_signature_raw.hex(),
        "opaque_common_body_region_length": len(common) if common is not None else None,
        "opaque_common_body_region_sha256": (
            sha256(common).hexdigest() if common is not None else None
        ),
        "opaque_after_701_length": len(tail) if tail is not None else None,
        "opaque_after_701_sha256": (
            sha256(tail).hexdigest() if tail is not None else None
        ),
    }


def _observer_snapshot(
    evidence: AreaSplitEvidenceObserver,
    windows: Sequence[str],
) -> dict[str, Any]:
    groups = evidence.complete_on_ari_sets(windows)["complete"]
    normalized_groups = [
        {key: value for key, value in item.items() if key not in {"observed_at", "identity_sha256", "segment_original_lengths", "segment_original_sha256", "window", "segment_count", "opaque_remainder_length", "opaque_remainder_sha256", "observed_context_class", "structural_error"}}
        | {"windows": [item["window"]]}
        for item in groups
    ]
    return {
        "on_mi": evidence.on_mi(windows),
        "area_set": evidence.area_set(windows),
        "on_ari": normalized_groups,
        "special_contour": [],
    }


def _capture_special_snapshot(
    records: Sequence[Mapping[str, Any]],
    windows: Sequence[str],
) -> list[dict[str, Any]]:
    selected = set(windows)
    observations: list[dict[str, Any]] = []
    for record in records:
        if record.get("window") not in selected or record.get("command") not in {
            "getSpecialContour",
            "onSpecialContour",
            "setSpecialContour",
        }:
            continue
        for segment in record.get("opaque_segments", []):
            original = segment.get("representations", {}).get("original")
            if not isinstance(original, Mapping):
                continue
            observations.append(
                {
                    "command": record.get("command"),
                    "direction": record.get("direction"),
                    "source_path": segment.get("source_path"),
                    "byte_length": original.get("byte_length"),
                    "sha256": original.get("sha256"),
                }
            )
    return observations


def _snapshot_stability(
    first: Mapping[str, Any],
    second: Mapping[str, Any],
) -> dict[str, Any]:
    checks = {
        "request_associated_onMI": _reference_value_check(
            _request_on_mi(first["on_mi"]),
            _request_on_mi(second["on_mi"]),
            _request_on_mi(first["on_mi"]),
            key_fields=("association",),
            value_fields=_ON_MI_VALUE_FIELDS,
        ),
        "getAreaSet": _reference_value_check(
            first["area_set"],
            second["area_set"],
            first["area_set"],
            key_fields=("mid", "aid", "type"),
            value_fields=("info_size", "subsets_length", "subsets_sha256"),
        ),
        "grouped_onArI": _reference_value_check(
            first["on_ari"],
            second["on_ari"],
            first["on_ari"],
            key_fields=("mid", "type", "using", "serial"),
            value_fields=_ON_ARI_VALUE_FIELDS,
        ),
    }
    passed = all(check["status"] == "passed" for check in checks.values())
    return {
        "status": "passed" if passed else "inconclusive",
        "checks": checks,
    }


def _combine_snapshots(
    first: Mapping[str, Any],
    second: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        family: [*first[family], *second[family]]
        for family in ("on_mi", "area_set", "on_ari", "special_contour")
    }


def _snapshot_delta(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "onMI": _family_delta(
            before["on_mi"],
            after["on_mi"],
            key_fields=("association",),
            value_fields=_ON_MI_VALUE_FIELDS,
        ),
        "getAreaSet": _family_delta(
            before["area_set"],
            after["area_set"],
            key_fields=("mid", "aid", "type"),
            value_fields=("info_size", "subsets_length", "subsets_sha256"),
        ),
        "grouped_onArI": _family_delta(
            before["on_ari"],
            after["on_ari"],
            key_fields=("mid", "type", "using", "serial"),
            value_fields=_ON_ARI_VALUE_FIELDS,
        ),
        "SpecialContour": _family_delta(
            before["special_contour"],
            after["special_contour"],
            key_fields=("command", "direction", "source_path"),
            value_fields=("byte_length", "sha256"),
        ),
        "presence_absence_is_byte_delta": False,
    }


def _family_delta(
    before: Sequence[Mapping[str, Any]],
    after: Sequence[Mapping[str, Any]],
    *,
    key_fields: Sequence[str],
    value_fields: Sequence[str],
) -> dict[str, Any]:
    before_values = _value_set(before, key_fields, value_fields)
    after_values = _value_set(after, key_fields, value_fields)
    if not before_values and not after_values:
        status = "not-observed"
    elif not before_values:
        status = "after-only"
    elif not after_values:
        status = "before-only"
    elif before_values == after_values:
        status = "unchanged"
    else:
        status = "value-changed"
    return {
        "status": status,
        "before_variant_count": len(before_values),
        "after_variant_count": len(after_values),
        "before": _deduplicated_metadata(before, (*key_fields, *value_fields)),
        "after": _deduplicated_metadata(after, (*key_fields, *value_fields)),
        "byte_delta_proven": False,
    }


def _deduplicated_metadata(
    items: Sequence[Mapping[str, Any]],
    fields: Sequence[str],
) -> list[dict[str, Any]]:
    values = {
        tuple((field, item.get(field)) for field in fields)
        for item in items
    }
    return [dict(value) for value in sorted(values, key=repr)]


def _validate_approved_original(snapshot: Mapping[str, Any]) -> None:
    area = _matching(snapshot["area_set"], _ORIGINAL_AREA_AR, ("mid", "aid", "type"))
    on_ari = _matching(snapshot["on_ari"], _ORIGINAL_ON_ARI, ("mid", "type", "serial"))
    if not any(_fields_equal(item, _ORIGINAL_AREA_AR, _ORIGINAL_AREA_AR) for item in area):
        raise AreaMergeReferenceError("Approved original AreaSet ar target mismatch")
    if not any(_fields_equal(item, _ORIGINAL_ON_ARI, _ORIGINAL_ON_ARI) for item in on_ari):
        raise AreaMergeReferenceError("Approved original grouped onArI target mismatch")


def _reference_value_check(
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
        return {"status": "failed", "reason": "missing-comparable-reference-values"}
    if first_values != second_values:
        return {"status": "failed", "reason": "pre-merge-app-init-values-differ"}
    if first_values != reference_values:
        return {"status": "failed", "reason": "current-state-does-not-match-p2-09c-split-state"}
    return {
        "status": "passed",
        "reason": None,
        "variant_count": len(first_values),
        "reference_capture_id": _REFERENCE_CAPTURE_ID,
    }


def _optional_direct_group_check(
    first: Sequence[Mapping[str, Any]],
    second: Sequence[Mapping[str, Any]],
    reference: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if not first and not second:
        return {
            "status": "not-observed",
            "reason": None,
            "required_for_gate": False,
        }
    if not first or not second:
        return {"status": "failed", "reason": "serial-3-type-0-observed-in-only-one-round"}
    check = _reference_value_check(
        first,
        second,
        reference,
        key_fields=("mid", "type", "using", "serial"),
        value_fields=_ON_ARI_VALUE_FIELDS,
    )
    check["required_for_gate"] = True
    return check


def _target_assessment(
    observations: Sequence[Mapping[str, Any]],
    expected: Mapping[str, Any],
    *,
    key_fields: Sequence[str],
    value_fields: Sequence[str],
) -> dict[str, Any]:
    matching = _matching(observations, expected, key_fields)
    exact = [item for item in matching if _fields_equal(item, expected, value_fields)]
    windows = sorted({window for item in matching for window in _windows(item)})
    variants = _value_set(matching, key_fields, value_fields)
    only_expected_variant = bool(exact) and len(variants) == 1
    return {
        "status": (
            "exact-match-observed" if only_expected_variant else "different-or-missing"
        ),
        "expected": {key: expected[key] for key in (*key_fields, *value_fields)},
        "observed": _deduplicated_metadata(
            matching,
            (*key_fields, *value_fields),
        ),
        "observed_variants": len(variants),
        "observed_windows": windows,
        "post_state_stable_across_windows": len(variants) == 1 and len(windows) >= 2,
    }


def _invariant_assessment(
    original: Sequence[Mapping[str, Any]],
    after: Sequence[Mapping[str, Any]],
    *,
    key_fields: Sequence[str],
    value_fields: Sequence[str],
) -> dict[str, Any]:
    left = _value_set(original, key_fields, value_fields)
    right = _value_set(after, key_fields, value_fields)
    return {
        "status": "unchanged" if left and left == right else "not-unchanged",
        "original_variant_count": len(left),
        "post_merge_variant_count": len(right),
    }


def _request_on_mi(items: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [item for item in items if item["association"] == "request-associated"]


def _type_selected(items: Sequence[Mapping[str, Any]], value: str) -> list[Mapping[str, Any]]:
    return [item for item in items if item["type"] == value]


def _serial_three_type_zero(items: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [item for item in items if item["serial"] == 3 and item["type"] == "0"]


def _value_set(
    items: Sequence[Mapping[str, Any]],
    key_fields: Sequence[str],
    value_fields: Sequence[str],
) -> set[tuple[Any, ...]]:
    return {
        tuple(item.get(field) for field in (*key_fields, *value_fields)) for item in items
    }


def _matching(
    items: Sequence[Mapping[str, Any]],
    expected: Mapping[str, Any],
    key_fields: Sequence[str],
) -> list[Mapping[str, Any]]:
    return [item for item in items if all(item.get(key) == expected[key] for key in key_fields)]


def _fields_equal(
    item: Mapping[str, Any],
    expected: Mapping[str, Any],
    fields: Sequence[str] | Mapping[str, Any],
) -> bool:
    return all(item.get(field) == expected[field] for field in fields)


def _windows(item: Mapping[str, Any]) -> Sequence[str]:
    if "windows" in item:
        windows = item["windows"]
        if isinstance(windows, list) and all(
            isinstance(window, str) for window in windows
        ):
            return cast("list[str]", windows)
        return []
    window = item.get("window")
    return [window] if isinstance(window, str) else []


def _record_data(record: VerifiedArtifactRecord) -> Mapping[str, Any]:
    envelope = record.sanitized_envelope
    if not isinstance(envelope, dict):
        raise AreaMergeReferenceError("Reference envelope is not an object")
    try:
        data = envelope["body"]["data"]
    except (KeyError, TypeError) as err:
        raise AreaMergeReferenceError("Reference body.data is missing") from err
    if not isinstance(data, dict):
        raise AreaMergeReferenceError("Reference body.data is not an object")
    return data


def _segment(record: VerifiedArtifactRecord, path: str) -> Any:
    matches = [segment for segment in record.opaque_segments if segment.source_path == path]
    if len(matches) != 1:
        message = f"Expected one verified opaque segment at {path}"
        raise AreaMergeReferenceError(message)
    return matches[0]


def _segment_int(record: VerifiedArtifactRecord, path: str, fallback: Any) -> int:
    if isinstance(fallback, int):
        return fallback
    raw = _segment(record, path).raw
    parsed = orjson.loads(raw)
    if not isinstance(parsed, int):
        message = f"Expected integer at {path}"
        raise AreaMergeReferenceError(message)
    return parsed
