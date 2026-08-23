"""Read-only three-state structural differentials for controlled GOAT captures."""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from hashlib import sha256
from typing import TYPE_CHECKING, Any, Literal

from .goat_map_delta import (
    ArtifactDeltaError,
    VerifiedArtifactRecord,
    VerifiedOpaqueSegment,
    VerifiedPhase2Artifact,
    load_verified_phase2_artifact,
)
from .goat_map_on_ari_framing import collect_grouped_on_ari_observations
from .goat_map_representation import (
    RepresentationDecodeError,
    decode_strict_base64_representation,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence
    from pathlib import Path

_SPLIT_CAPTURE_ID = "212a37d365b54f77bbb6c0424ff94246"
_MERGE_CAPTURE_ID = "fad46b96aab44781881ce37b230ecf39"
_INFO_PATH = "$.body.data.info"
_SUBSETS_PATH = "$.body.data.subsets"
_INFO_SIZE_PATH = "$.body.data.infoSize"
_AID_PATH = "$.body.data.aid"
_REGION_END_AFTER_701 = 702

type StateName = Literal["A", "B", "C"]
type TaggedByte = tuple[int, int]
type AlignmentColumn = tuple[TaggedByte | None, TaggedByte | None, TaggedByte | None]


class ThreeStateAnalysisError(ValueError):
    """The immutable controlled captures cannot be compared unambiguously."""


@dataclass(frozen=True, slots=True)
class _StateBytes:
    name: StateName
    capture_id: str
    windows: tuple[str, ...]
    raw: bytes
    info_size: int
    mid: str
    metadata: dict[str, Any]


def analyze_controlled_area_three_state(
    split_artifact_dir: Path,
    merge_artifact_dir: Path,
    *,
    expected_split_capture_id: str = _SPLIT_CAPTURE_ID,
    expected_merge_capture_id: str = _MERGE_CAPTURE_ID,
) -> dict[str, Any]:
    """Compare original, post-Divide, and post-Merge bytes without interpretation."""
    try:
        split = load_verified_phase2_artifact(split_artifact_dir)
        merge = load_verified_phase2_artifact(merge_artifact_dir)
    except ArtifactDeltaError as err:
        raise ThreeStateAnalysisError(str(err)) from err
    _require_capture(split, expected_split_capture_id, "split")
    _require_capture(merge, expected_merge_capture_id, "merge recovery")

    a_windows = (f"{split.phase}:pre-split-app-init-2",)
    b_windows = (f"{split.phase}:post-split-reopen",)
    c_windows = (
        f"{merge.phase}:post-merge-app-init-1",
        f"{merge.phase}:post-merge-app-init-2",
    )
    states: dict[StateName, tuple[VerifiedPhase2Artifact, tuple[str, ...]]] = {
        "A": (split, a_windows),
        "B": (split, b_windows),
        "C": (merge, c_windows),
    }

    area_states = tuple(
        _area_set_state(name, artifact, windows, area_type="ar")
        for name, (artifact, windows) in states.items()
    )
    on_ari_states = tuple(
        _on_ari_state(name, artifact, windows)
        for name, (artifact, windows) in states.items()
    )

    area_original = analyze_three_state_bytes(
        *(item.raw for item in area_states),
        representation="original-representation-bytes",
    )
    area_decoded = _strict_base64_three_state(area_states)
    on_ari_full = analyze_three_state_bytes(
        *(item.raw for item in on_ari_states),
        representation="strict-base64-derived-segment-concatenation",
    )

    controls = _control_assessments(states)
    report: dict[str, Any] = {
        "schema_version": "goat-controlled-area-three-state/v1",
        "analysis_version": "goat-controlled-area-three-state/v1",
        "analysis_kind": "read-only-byte-preserving-three-state-differential",
        "artifact_modification": False,
        "opaque_full_values_in_report": False,
        "semantic_parser": False,
        "geometry_interpretation": False,
        "states": {
            item.name: {
                "capture_id": item.capture_id,
                "windows": list(item.windows),
                "mid": item.mid,
            }
            for item in area_states
        },
        "getAreaSet_type_ar": {
            "state_metadata": _state_metadata(area_states),
            "original_representation": area_original,
            "strict_base64_derived_representation": area_decoded,
        },
        "grouped_onArI": {
            "selection": {
                "mid": "1",
                "type": "0",
                "serial": 3,
                "complete_index_set_required": True,
            },
            "state_metadata": _state_metadata(on_ari_states),
            "full_derived_stream": on_ari_full,
            "structural_regions": _on_ari_region_analysis(on_ari_states),
            "similarity_assessment": _similarity_assessment(on_ari_full),
        },
        "controls": controls,
        "hypothesis_assessment": _hypothesis_assessment(),
        "conclusion": (
            "The observed AreaSet/onArI encoding is not solely determined by "
            "the visible pre/post work-area topology in this controlled cycle. "
            "Persistent or regenerated structural state is required to explain "
            "the stable third encoding, but its semantics are unknown."
        ),
        "interpretation_guard": (
            "Alignment is deterministic byte-sequence alignment only. Matching "
            "spans, gaps, offsets, lengths, and digests do not identify fields, "
            "records, coordinates, topology, or geometry."
        ),
    }
    _require_expected_controls(controls)
    return report


def analyze_three_state_bytes(
    a: bytes,
    b: bytes,
    c: bytes,
    *,
    representation: str,
) -> dict[str, Any]:
    """Return deterministic metadata-only alignment and absolute-offset results."""
    columns = _three_way_alignment(a, b, c)
    aligned_spans = _coalesce_columns(columns)
    absolute_columns = tuple(
        (
            (offset, a[offset]) if offset < len(a) else None,
            (offset, b[offset]) if offset < len(b) else None,
            (offset, c[offset]) if offset < len(c) else None,
        )
        for offset in range(max(len(a), len(b), len(c)))
    )
    return {
        "representation": representation,
        "states": {
            name: {"length": len(raw), "sha256": sha256(raw).hexdigest()}
            for name, raw in zip(("A", "B", "C"), (a, b, c), strict=True)
        },
        "whole_value_classification": _classify_values(a, b, c),
        "common_prefix_length": _common_prefix_three(a, b, c),
        "common_suffix_length": _common_suffix_three(a, b, c),
        "absolute_offset_comparison": {
            "basis": (
                "same numeric offset only; variable-length edits may make later "
                "absolute offsets structurally non-comparable"
            ),
            "spans": _coalesce_columns(absolute_columns),
            "classification_totals": _classification_totals(
                _coalesce_columns(absolute_columns)
            ),
        },
        "alignment": {
            "method": "difflib-sequence-matcher-progressive-reference-A-v1",
            "autojunk": False,
            "reference_state": "A",
            "gap_is_a_structural_difference": True,
            "spans": aligned_spans,
            "classification_totals": _classification_totals(aligned_spans),
            "stable_internal_islands": [
                span
                for span in aligned_spans
                if span["classification"] == "invariant" and span["column_count"] >= 4
            ],
        },
        "pairwise_diffs": {
            "A_to_B": _pairwise_diff(a, b),
            "A_to_C": _pairwise_diff(a, c),
            "B_to_C": _pairwise_diff(b, c),
        },
    }


def _area_set_state(
    name: StateName,
    artifact: VerifiedPhase2Artifact,
    windows: Sequence[str],
    *,
    area_type: str,
) -> _StateBytes:
    records = [
        record
        for record in artifact.records
        if record.window in windows
        and record.command == "getAreaSet"
        and record.direction == "response"
        and _data(record).get("type") == area_type
    ]
    variants: dict[tuple[bytes, int, str, str], list[str]] = {}
    for record in records:
        raw = _segment(record, _SUBSETS_PATH).raw
        info_size = _segment_int(record, _INFO_SIZE_PATH)
        mid = str(_data(record).get("mid"))
        aid = _segment(record, _AID_PATH).raw.decode("utf-8")
        variants.setdefault((raw, info_size, mid, aid), []).append(record.observed_at)
    if len(variants) != 1:
        msg = f"State {name} does not contain one stable getAreaSet type={area_type} variant"
        raise ThreeStateAnalysisError(msg)
    (raw, info_size, mid, aid), timestamps = next(iter(variants.items()))
    return _StateBytes(
        name=name,
        capture_id=artifact.capture_id,
        windows=tuple(windows),
        raw=raw,
        info_size=info_size,
        mid=mid,
        metadata={"aid_raw": aid, "type": area_type, "observed_at": sorted(timestamps)},
    )


def _on_ari_state(
    name: StateName,
    artifact: VerifiedPhase2Artifact,
    windows: Sequence[str],
) -> _StateBytes:
    observations, excluded = collect_grouped_on_ari_observations((artifact,))
    if any(set(item.get("windows", ())).intersection(windows) for item in excluded):
        msg = f"State {name} has an incomplete grouped onArI set"
        raise ThreeStateAnalysisError(msg)
    selected = [
        item
        for item in observations
        if set(item.windows).intersection(windows)
        and item.segment_set.identity.serial == 3
        and str(item.segment_set.identity.mid) == "1"
        and str(item.segment_set.identity.type) == "0"
    ]
    variants: dict[tuple[bytes, int, str], list[str]] = {}
    for item in selected:
        value = item.segment_set
        variants.setdefault(
            (
                value.derived_concatenation,
                int(value.identity.info_size),
                str(value.identity.using),
            ),
            [],
        ).append(item.first_timestamp)
    if len(variants) != 1:
        msg = f"State {name} does not contain one stable serial=3/type=0 onArI variant"
        raise ThreeStateAnalysisError(msg)
    (raw, info_size, using), timestamps = next(iter(variants.items()))
    return _StateBytes(
        name=name,
        capture_id=artifact.capture_id,
        windows=tuple(windows),
        raw=raw,
        info_size=info_size,
        mid="1",
        metadata={
            "serial": 3,
            "type": "0",
            "using": using,
            "observed_at": sorted(timestamps),
        },
    )


def _strict_base64_three_state(states: Sequence[_StateBytes]) -> dict[str, Any]:
    try:
        decoded = [
            decode_strict_base64_representation(item.raw.decode("ascii"))
            for item in states
        ]
    except (UnicodeDecodeError, RepresentationDecodeError) as err:
        raise ThreeStateAnalysisError(
            "AreaSet ar is not strict canonical Base64 in all three states"
        ) from err
    return analyze_three_state_bytes(
        *decoded,
        representation="strict-base64-derived-bytes",
    )


def _on_ari_region_analysis(states: Sequence[_StateBytes]) -> dict[str, Any]:
    if len(states) != 3:
        raise ThreeStateAnalysisError("Exactly three onArI states are required")
    values = (states[0].raw, states[1].raw, states[2].raw)
    return {
        "outer_structural_header_0_16": _slice_analysis(values, 0, 17),
        "context_signature_17_33": _slice_analysis(values, 17, 34),
        "opaque_remainder_from_34": _slice_analysis(values, 34, None),
        "absolute_34_701_comparison_window": {
            **_slice_analysis(values, 34, _REGION_END_AFTER_701),
            "boundary_scope": (
                "absolute comparison window; no common-body field is asserted "
                "for the observed c8 signature"
            ),
        },
        "opaque_tail_after_701": _slice_analysis(values, _REGION_END_AFTER_701, None),
    }


def _slice_analysis(
    values: tuple[bytes, bytes, bytes],
    start: int,
    end: int | None,
) -> dict[str, Any]:
    sliced = tuple(value[start:end] for value in values)
    result = analyze_three_state_bytes(
        *sliced,
        representation="derived-byte-region",
    )
    result["absolute_range"] = {"start": start, "end_exclusive": end}
    result["offset_origin"] = start
    return result


def _three_way_alignment(a: bytes, b: bytes, c: bytes) -> tuple[AlignmentColumn, ...]:
    b_aligned, b_insertions = _align_to_reference(a, b)
    c_aligned, c_insertions = _align_to_reference(a, c)
    columns: list[AlignmentColumn] = []
    for boundary in range(len(a) + 1):
        columns.extend(
            (None, left, right)
            for left, right in _align_insertions(
                b_insertions.get(boundary, ()), c_insertions.get(boundary, ())
            )
        )
        if boundary < len(a):
            columns.append(
                ((boundary, a[boundary]), b_aligned[boundary], c_aligned[boundary])
            )
    _verify_alignment_round_trip(columns, a, b, c)
    return tuple(columns)


def _align_to_reference(
    reference: bytes,
    other: bytes,
) -> tuple[list[TaggedByte | None], dict[int, tuple[TaggedByte, ...]]]:
    aligned: list[TaggedByte | None] = [None] * len(reference)
    insertions: dict[int, list[TaggedByte]] = {}
    matcher = SequenceMatcher(None, reference, other, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(i2 - i1):
                aligned[i1 + offset] = (j1 + offset, other[j1 + offset])
        elif tag == "replace":
            shared = min(i2 - i1, j2 - j1)
            for offset in range(shared):
                aligned[i1 + offset] = (j1 + offset, other[j1 + offset])
            if j1 + shared < j2:
                insertions.setdefault(i1 + shared, []).extend(
                    (offset, other[offset]) for offset in range(j1 + shared, j2)
                )
        elif tag == "insert":
            insertions.setdefault(i1, []).extend(
                (offset, other[offset]) for offset in range(j1, j2)
            )
    return aligned, {key: tuple(value) for key, value in insertions.items()}


def _align_insertions(
    left: Sequence[TaggedByte],
    right: Sequence[TaggedByte],
) -> tuple[tuple[TaggedByte | None, TaggedByte | None], ...]:
    left_values = bytes(item[1] for item in left)
    right_values = bytes(item[1] for item in right)
    columns: list[tuple[TaggedByte | None, TaggedByte | None]] = []
    matcher = SequenceMatcher(None, left_values, right_values, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            columns.extend(
                (left[i], right[j])
                for i, j in zip(range(i1, i2), range(j1, j2), strict=False)
            )
        elif tag == "replace":
            shared = min(i2 - i1, j2 - j1)
            columns.extend((left[i1 + n], right[j1 + n]) for n in range(shared))
            columns.extend((left[i], None) for i in range(i1 + shared, i2))
            columns.extend((None, right[j]) for j in range(j1 + shared, j2))
        elif tag == "delete":
            columns.extend((left[i], None) for i in range(i1, i2))
        elif tag == "insert":
            columns.extend((None, right[j]) for j in range(j1, j2))
    return tuple(columns)


def _coalesce_columns(columns: Sequence[AlignmentColumn]) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    pending: list[AlignmentColumn] = []
    pending_key: tuple[str, tuple[bool, bool, bool]] | None = None
    for column in columns:
        values = tuple(item[1] if item is not None else None for item in column)
        presence = (
            column[0] is not None,
            column[1] is not None,
            column[2] is not None,
        )
        key = (
            _classify_values(*values),
            presence,
        )
        if pending_key is not None and key != pending_key:
            reports.append(_span_report(pending, pending_key[0]))
            pending = []
        pending_key = key
        pending.append(column)
    if pending and pending_key is not None:
        reports.append(_span_report(pending, pending_key[0]))
    return reports


def _span_report(
    columns: Sequence[AlignmentColumn], classification: str
) -> dict[str, Any]:
    states: dict[str, dict[str, Any]] = {}
    for index, name in enumerate(("A", "B", "C")):
        present = [tagged for item in columns if (tagged := item[index]) is not None]
        raw = bytes(item[1] for item in present)
        states[name] = {
            "start": present[0][0] if present else None,
            "end_exclusive": present[-1][0] + 1 if present else None,
            "length": len(raw),
            "sha256": sha256(raw).hexdigest() if raw else None,
        }
    return {
        "classification": classification,
        "column_count": len(columns),
        "presence": {name: states[name]["length"] > 0 for name in ("A", "B", "C")},
        "states": states,
    }


def _pairwise_diff(left: bytes, right: bytes) -> dict[str, Any]:
    matcher = SequenceMatcher(None, left, right, autojunk=False)
    opcodes = matcher.get_opcodes()
    matched = sum(i2 - i1 for tag, i1, i2, _j1, _j2 in opcodes if tag == "equal")
    return {
        "common_prefix_length": _common_prefix_two(left, right),
        "common_suffix_length": _common_suffix_two(left, right),
        "matching_byte_count": matched,
        "sequence_matcher_ratio": matcher.ratio(),
        "spans": [
            {
                "operation": tag,
                "left": _range_digest(left, i1, i2),
                "right": _range_digest(right, j1, j2),
            }
            for tag, i1, i2, j1, j2 in opcodes
        ],
    }


def _range_digest(value: bytes, start: int, end: int) -> dict[str, Any]:
    selected = value[start:end]
    return {
        "start": start,
        "end_exclusive": end,
        "length": len(selected),
        "sha256": sha256(selected).hexdigest() if selected else None,
    }


def _classify_values(a: Any, b: Any, c: Any) -> str:
    if a == b == c:
        return "invariant"
    if a == c and a != b:
        return "topology-reversed"
    if b == c and a != b:
        return "persistent-post-edit"
    if a == b and a != c:
        return "merge-specific"
    return "state-or-operation-sensitive"


def _classification_totals(spans: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for span in spans:
        name = str(span["classification"])
        totals[name] = totals.get(name, 0) + int(span["column_count"])
    return dict(sorted(totals.items()))


def _similarity_assessment(full: Mapping[str, Any]) -> dict[str, Any]:
    pairwise = full["pairwise_diffs"]
    original = pairwise["A_to_C"]
    split = pairwise["B_to_C"]
    if original["sequence_matcher_ratio"] > split["sequence_matcher_ratio"]:
        closer = "original-A"
    elif original["sequence_matcher_ratio"] < split["sequence_matcher_ratio"]:
        closer = "split-B"
    else:
        closer = "equal-by-this-measure"
    return {
        "measure": "sequence-matcher-ratio-autojunk-false",
        "post_merge_C_is_closer_to": closer,
        "A_to_C_ratio": original["sequence_matcher_ratio"],
        "B_to_C_ratio": split["sequence_matcher_ratio"],
        "same_total_length_is_restoration": False,
    }


def _control_assessments(
    states: Mapping[StateName, tuple[VerifiedPhase2Artifact, Sequence[str]]],
) -> dict[str, Any]:
    on_mi = {
        name: _segment_variants(artifact, windows, "onMI", _INFO_PATH)
        for name, (artifact, windows) in states.items()
    }
    vw = {
        name: _area_type_variants(artifact, windows, "vw")
        for name, (artifact, windows) in states.items()
    }
    mids = {
        name: _observed_mids(artifact, windows)
        for name, (artifact, windows) in states.items()
    }
    special = {
        name: _special_contour_variants(artifact, windows)
        for name, (artifact, windows) in states.items()
    }
    return {
        "request_associated_onMI": _variant_control(on_mi),
        "AreaSet_vw": _variant_control(vw),
        "mid": {
            "status": "unchanged"
            if len({tuple(v) for v in mids.values()}) == 1
            else "changed",
            "values": mids,
        },
        "SpecialContour_comparable_values": _comparable_control(special),
    }


def _segment_variants(
    artifact: VerifiedPhase2Artifact,
    windows: Sequence[str],
    command: str,
    path: str,
) -> list[dict[str, Any]]:
    values = {
        (len(segment.raw), segment.sha256)
        for record in artifact.records
        if record.window in windows and record.command == command
        for segment in record.opaque_segments
        if segment.source_path == path
    }
    return [{"length": length, "sha256": digest} for length, digest in sorted(values)]


def _area_type_variants(
    artifact: VerifiedPhase2Artifact,
    windows: Sequence[str],
    area_type: str,
) -> list[dict[str, Any]]:
    values = {
        (
            len(_segment(record, _SUBSETS_PATH).raw),
            _segment(record, _SUBSETS_PATH).sha256,
        )
        for record in artifact.records
        if record.window in windows
        and record.command == "getAreaSet"
        and record.direction == "response"
        and _data(record).get("type") == area_type
    }
    return [{"length": length, "sha256": digest} for length, digest in sorted(values)]


def _observed_mids(
    artifact: VerifiedPhase2Artifact,
    windows: Sequence[str],
) -> list[str]:
    mids = {
        str(_data(record)["mid"])
        for record in artifact.records
        if record.window in windows and "mid" in _data(record)
    }
    return sorted(mids)


def _special_contour_variants(
    artifact: VerifiedPhase2Artifact,
    windows: Sequence[str],
) -> dict[str, list[tuple[int, str]]]:
    values: dict[str, set[tuple[int, str]]] = {}
    for record in artifact.records:
        if record.window not in windows or record.command not in {
            "getSpecialContour",
            "onSpecialContour",
            "setSpecialContour",
        }:
            continue
        for segment in record.opaque_segments:
            key = f"{record.command}|{record.direction}|{segment.source_path}"
            values.setdefault(key, set()).add((len(segment.raw), segment.sha256))
    return {key: sorted(items) for key, items in sorted(values.items())}


def _variant_control(
    values: Mapping[StateName, list[dict[str, Any]]],
) -> dict[str, Any]:
    serialized = {
        tuple((item["length"], item["sha256"]) for item in value)
        for value in values.values()
    }
    return {
        "status": "unchanged"
        if len(serialized) == 1 and bool(serialized)
        else "changed-or-missing",
        "values": dict(values),
    }


def _comparable_control(
    values: Mapping[StateName, Mapping[str, list[tuple[int, str]]]],
) -> dict[str, Any]:
    common = set.intersection(*(set(item) for item in values.values()))
    comparisons = {
        key: {state: value[key] for state, value in values.items()}
        for key in sorted(common)
    }
    changed = [
        key
        for key, item in comparisons.items()
        if len({tuple(v) for v in item.values()}) != 1
    ]
    return {
        "status": "unchanged" if comparisons and not changed else "changed-or-missing",
        "comparable_key_count": len(comparisons),
        "changed_keys": changed,
        "values": comparisons,
        "non_comparable_keys_by_state": {
            state: sorted(set(item) - common) for state, item in values.items()
        },
    }


def _hypothesis_assessment() -> dict[str, Any]:
    return {
        "rejected_or_weakened": [
            {
                "hypothesis": "visible-work-area-topology-solely-determines-encoding",
                "status": "rejected-in-this-controlled-cycle",
                "basis": "A and C have restored visible topology but different stable bytes",
            },
            {
                "hypothesis": "inverse-merge-restores-pre-divide-bytes",
                "status": "rejected-in-this-controlled-cycle",
                "basis": "both AreaSet ar and grouped onArI are byte-distinct in C",
            },
            {
                "hypothesis": "equal-infoSize-and-total-length-imply-equal-onArI-state",
                "status": "rejected",
                "basis": "A and C are both 1651/6933 but have different digests",
            },
        ],
        "supported": [
            {
                "hypothesis": "divide-and-merge-produce-repeatable-structural-state-changes",
                "status": "supported-in-this-controlled-cycle",
            },
            {
                "hypothesis": "some-post-divide-structure-persists-after-merge",
                "status": "supported-structurally",
                "basis": "B and C share the exact c8 context signature while A uses b4",
            },
            {
                "hypothesis": "length-restoration-can-occur-without-byte-restoration",
                "status": "supported",
                "basis": "grouped onArI C restores A length/infoSize but not digest/signature",
            },
        ],
    }


def _state_metadata(states: Sequence[_StateBytes]) -> dict[str, Any]:
    return {
        item.name: {
            "capture_id": item.capture_id,
            "windows": list(item.windows),
            "length": len(item.raw),
            "sha256": sha256(item.raw).hexdigest(),
            "infoSize": item.info_size,
            "mid": item.mid,
            **item.metadata,
        }
        for item in states
    }


def _require_expected_controls(controls: Mapping[str, Any]) -> None:
    expected = {
        "request_associated_onMI": "unchanged",
        "AreaSet_vw": "unchanged",
        "mid": "unchanged",
        "SpecialContour_comparable_values": "unchanged",
    }
    failures = [
        name for name, status in expected.items() if controls[name]["status"] != status
    ]
    if failures:
        msg = f"Three-state control invariants failed: {', '.join(failures)}"
        raise ThreeStateAnalysisError(msg)


def _require_capture(
    artifact: VerifiedPhase2Artifact,
    expected_capture_id: str,
    label: str,
) -> None:
    if artifact.capture_id != expected_capture_id:
        msg = f"Unexpected {label} capture ID"
        raise ThreeStateAnalysisError(msg)


def _data(record: VerifiedArtifactRecord) -> Mapping[str, Any]:
    value: Any = record.sanitized_envelope
    if isinstance(value, dict) and isinstance(value.get("body"), dict):
        value = value["body"]
    if isinstance(value, dict) and isinstance(value.get("data"), dict):
        value = value["data"]
    return value if isinstance(value, dict) else {}


def _segment(record: VerifiedArtifactRecord, path: str) -> VerifiedOpaqueSegment:
    matches = [item for item in record.opaque_segments if item.source_path == path]
    if len(matches) != 1:
        msg = f"Expected exactly one opaque segment at {path} in sequence {record.sequence}"
        raise ThreeStateAnalysisError(msg)
    return matches[0]


def _segment_int(record: VerifiedArtifactRecord, path: str) -> int:
    raw = _segment(record, path).raw
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as err:
        msg = f"Non-ASCII integer representation at {path}"
        raise ThreeStateAnalysisError(msg) from err
    if not text.isdigit() or (text != "0" and text.startswith("0")):
        msg = f"Non-canonical decimal integer at {path}"
        raise ThreeStateAnalysisError(msg)
    return int(text)


def _verify_alignment_round_trip(
    columns: Iterable[AlignmentColumn],
    a: bytes,
    b: bytes,
    c: bytes,
) -> None:
    rebuilt_values: list[bytes] = []
    for index in range(3):
        tagged = [value for item in columns if (value := item[index]) is not None]
        rebuilt_values.append(bytes(value[1] for value in tagged))
    rebuilt = tuple(rebuilt_values)
    if rebuilt != (a, b, c):
        raise AssertionError(
            "Internal three-state alignment did not preserve input bytes"
        )


def _common_prefix_three(a: bytes, b: bytes, c: bytes) -> int:
    return next(
        (
            index
            for index, values in enumerate(zip(a, b, c, strict=False))
            if len(set(values)) != 1
        ),
        min(len(a), len(b), len(c)),
    )


def _common_suffix_three(a: bytes, b: bytes, c: bytes) -> int:
    limit = min(len(a), len(b), len(c))
    for count in range(limit):
        if len({a[-count - 1], b[-count - 1], c[-count - 1]}) != 1:
            return count
    return limit


def _common_prefix_two(left: bytes, right: bytes) -> int:
    return next(
        (
            index
            for index, values in enumerate(zip(left, right, strict=False))
            if values[0] != values[1]
        ),
        min(len(left), len(right)),
    )


def _common_suffix_two(left: bytes, right: bytes) -> int:
    limit = min(len(left), len(right))
    for count in range(limit):
        if left[-count - 1] != right[-count - 1]:
            return count
    return limit
