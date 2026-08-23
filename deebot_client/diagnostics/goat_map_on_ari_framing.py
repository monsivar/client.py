"""Read-only framing research for grouped opaque onArI-derived bytes."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from itertools import combinations
from typing import TYPE_CHECKING, Any, Literal

import orjson

from .goat_map_delta import (
    ArtifactDeltaError,
    VerifiedArtifactRecord,
    VerifiedOpaqueSegment,
    VerifiedPhase2Artifact,
    load_verified_phase2_artifact,
)
from .goat_map_segment_grouping import (
    EnvelopeValue,
    OpaqueSegmentInput,
    OpaqueSegmentSet,
    SegmentGroupingError,
    assemble_opaque_segment_set,
    normalize_segment_cardinality,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

_ANALYSIS_VERSION = "goat-onari-grouped-framing/v1"
_INFO_PATH = "$.body.data.info"
_PREVIEW_BYTES = 64
_INTEGER_WIDTHS = (2, 4, 8)
type ByteOrder = Literal["little", "big"]
_BYTE_ORDERS: tuple[ByteOrder, ...] = ("little", "big")
_MAX_REPORTED_FIELDS_PER_RELATION = 8
_KNOWN_MAGICS = (
    ("gzip", b"\x1f\x8b"),
    ("zip", b"PK\x03\x04"),
    ("bzip2", b"BZh"),
    ("xz", b"\xfd7zXZ\x00"),
    ("zstd", b"\x28\xb5\x2f\xfd"),
    ("lz4-frame", b"\x04\x22\x4d\x18"),
)


class OnAriFramingResearchError(ValueError):
    """The immutable corpus cannot be analyzed safely or consistently."""


@dataclass(frozen=True, slots=True)
class GroupedOnAriObservation:
    """One complete opaque segment set with non-sensitive capture context."""

    capture_id: str
    phase: str
    mower_state: str
    windows: tuple[str, ...]
    first_timestamp: str
    event_transports: tuple[str, ...]
    associated_control_transports: tuple[str, ...]
    associated_control_delta_microseconds: tuple[int, ...]
    roles: tuple[str, ...]
    segment_set: OpaqueSegmentSet


@dataclass(frozen=True, slots=True)
class _RecordContext:
    record: VerifiedArtifactRecord
    role: str
    control_transport: str | None
    control_delta_microseconds: int | None


def analyze_on_ari_grouped_framing_corpus(
    artifact_dirs: Sequence[Path],
) -> dict[str, Any]:
    """Verify artifacts and analyze complete envelope groups without mutation."""
    if not artifact_dirs:
        raise OnAriFramingResearchError("At least one Phase 2 artifact is required")
    try:
        artifacts = sorted(
            (load_verified_phase2_artifact(path) for path in artifact_dirs),
            key=lambda item: (item.phase, item.capture_id),
        )
    except ArtifactDeltaError as err:
        raise OnAriFramingResearchError(str(err)) from err
    capture_ids = [artifact.capture_id for artifact in artifacts]
    if len(capture_ids) != len(set(capture_ids)):
        raise OnAriFramingResearchError("Corpus contains duplicate capture IDs")

    observations, excluded = collect_grouped_on_ari_observations(artifacts)
    report = analyze_grouped_on_ari_framing(observations)
    report["corpus"]["captures"] = [
        {
            "capture_id": artifact.capture_id,
            "phase": artifact.phase,
            "mower_state": artifact.mower_state,
        }
        for artifact in artifacts
    ]
    report["corpus"]["excluded_groups"] = excluded
    report["corpus"]["excluded_group_count"] = len(excluded)
    return report


def collect_grouped_on_ari_observations(
    artifacts: Sequence[VerifiedPhase2Artifact],
) -> tuple[list[GroupedOnAriObservation], list[dict[str, Any]]]:
    """Collect complete structural groups from already verified artifacts."""
    observations: list[GroupedOnAriObservation] = []
    excluded: list[dict[str, Any]] = []
    for artifact in artifacts:
        artifact_observations, artifact_excluded = _artifact_observations(artifact)
        observations.extend(artifact_observations)
        excluded.extend(artifact_excluded)
    return observations, excluded


def analyze_grouped_on_ari_framing(
    observations: Sequence[GroupedOnAriObservation],
) -> dict[str, Any]:
    """Produce deterministic metadata-only framing research for complete sets."""
    ordered = sorted(observations, key=_observation_sort_key)
    reports = [_group_report(item) for item in ordered]
    comparisons = _pairwise_comparisons(ordered, reports)
    return {
        "schema_version": "goat-onari-grouped-framing-report/v1",
        "analysis_version": _ANALYSIS_VERSION,
        "analysis_kind": "opaque-read-only-grouped-framing-research",
        "artifact_modification": False,
        "framing_parser_implemented": False,
        "codec_or_decompression_attempted": False,
        "opaque_full_values_in_report": False,
        "corpus": {
            "capture_count": len({item.capture_id for item in ordered}),
            "complete_group_count": len(ordered),
            "serial_distribution": _count_values(
                item.segment_set.identity.serial for item in ordered
            ),
            "role_distribution": _count_values(
                role for item in ordered for role in item.roles
            ),
        },
        "groups": reports,
        "cross_group_structure": {
            "common_across_all": _common_across_all(ordered),
            "pairwise_comparisons": comparisons,
            "comparison_categories": _comparison_categories(comparisons),
        },
        "field_candidates": _field_candidates(ordered),
        "signature_assessment": {
            "tested": "known-magic-only-without-codec-execution",
            "groups_with_matches": [
                {
                    "group_id": report["group_id"],
                    "matches": report["structural_measurements"]["known_magic_matches"],
                }
                for report in reports
                if report["structural_measurements"]["known_magic_matches"]
            ],
        },
        "trailer_integrity_assessment": {
            "tested": False,
            "reason": "no-concrete-trailer-field-candidate",
        },
        "interpretation_guard": (
            "Offsets, integer readings, repetitions, signatures, lengths, and "
            "digests are structural observations only. Candidate fields are not "
            "consumed by a parser and the derived bytes remain uninterpreted."
        ),
    }


def _artifact_observations(
    artifact: VerifiedPhase2Artifact,
) -> tuple[list[GroupedOnAriObservation], list[dict[str, Any]]]:
    grouped: dict[
        tuple[str, int, EnvelopeValue, EnvelopeValue, EnvelopeValue, EnvelopeValue],
        list[tuple[OpaqueSegmentInput, _RecordContext]],
    ] = defaultdict(list)
    excluded: list[dict[str, Any]] = []
    control_markers = _explicit_control_markers(artifact.records)
    preceding_on_mi: tuple[VerifiedArtifactRecord, str] | None = None
    for record in sorted(artifact.records, key=lambda item: item.sequence):
        if record.command == "onMI" and record.direction == "event":
            preceding_on_mi = (record, _on_mi_role(record))
            continue
        if record.command != "onArI" or record.direction != "event":
            continue
        try:
            segment_input = _segment_input(record)
        except OnAriFramingResearchError as err:
            excluded.append(
                {
                    "capture_id": artifact.capture_id,
                    "sequence": record.sequence,
                    "reason": type(err).__name__,
                }
            )
            continue
        role = preceding_on_mi[1] if preceding_on_mi is not None else "unclassified"
        control_transport = None
        control_delta = None
        marker = control_markers.get(record.window)
        if role == "request-associated" and marker is not None:
            control_transport = marker.transport
            control_delta = _timestamp_delta_microseconds(
                record.observed_at,
                marker.observed_at,
            )
        normalized_serial = normalize_segment_cardinality(
            "serial",
            segment_input.serial,
            allow_zero=False,
        )
        identity = (
            segment_input.batid,
            normalized_serial,
            segment_input.info_size,
            segment_input.mid,
            segment_input.type,
            segment_input.using,
        )
        grouped[identity].append(
            (
                segment_input,
                _RecordContext(
                    record=record,
                    role=role,
                    control_transport=control_transport,
                    control_delta_microseconds=control_delta,
                ),
            )
        )

    observations = []
    for identity, items in grouped.items():
        try:
            segment_set = assemble_opaque_segment_set([segment for segment, _ in items])
        except SegmentGroupingError as err:
            excluded.append(
                {
                    "capture_id": artifact.capture_id,
                    "identity_digest": _identity_digest(artifact.capture_id, identity),
                    "reason": type(err).__name__,
                }
            )
            continue
        contexts = [context for _, context in items]
        observations.append(
            GroupedOnAriObservation(
                capture_id=artifact.capture_id,
                phase=artifact.phase,
                mower_state=artifact.mower_state,
                windows=tuple(sorted({item.record.window for item in contexts})),
                first_timestamp=min(item.record.observed_at for item in contexts),
                event_transports=tuple(
                    sorted({item.record.transport for item in contexts})
                ),
                associated_control_transports=tuple(
                    sorted(
                        {
                            item.control_transport
                            for item in contexts
                            if item.control_transport is not None
                        }
                    )
                ),
                associated_control_delta_microseconds=tuple(
                    sorted(
                        {
                            item.control_delta_microseconds
                            for item in contexts
                            if item.control_delta_microseconds is not None
                        }
                    )
                ),
                roles=tuple(sorted({item.role for item in contexts})),
                segment_set=segment_set,
            )
        )
    return observations, excluded


def _segment_input(record: VerifiedArtifactRecord) -> OpaqueSegmentInput:
    info = _segment(record, _INFO_PATH)
    if info is None:
        raise OnAriFramingResearchError("onArI record has no opaque info segment")
    try:
        representation = info.raw.decode("ascii")
    except UnicodeDecodeError as err:
        raise OnAriFramingResearchError("onArI info is not ASCII") from err
    batid = _required_scalar(record, "$.body.data.batid")
    if not isinstance(batid, str) or not batid:
        raise OnAriFramingResearchError("onArI batid is not a non-empty string")
    return OpaqueSegmentInput(
        batid=batid,
        serial=_required_decimal_integer(record, "$.body.data.serial"),
        index=_required_decimal_integer(record, "$.body.data.index"),
        info_size=_required_envelope_value(record, "$.body.data.infoSize"),
        mid=_required_envelope_value(record, "$.body.data.mid"),
        type=_required_envelope_value(record, "$.body.data.type"),
        using=_required_envelope_value(record, "$.body.data.using"),
        representation=representation,
    )


def _on_mi_role(record: VerifiedArtifactRecord) -> str:
    info = _segment(record, _INFO_PATH)
    if info is None:
        return "unclassified"
    if len(info.raw) == 876:
        return "request-associated"
    if len(info.raw) == 52:
        return "cadence-associated"
    return "unclassified"


def _group_report(observation: GroupedOnAriObservation) -> dict[str, Any]:
    segment_set = observation.segment_set
    raw = segment_set.derived_concatenation
    leading_preview = _non_complete_preview(raw)
    identity = segment_set.identity
    return {
        "group_id": _group_id(observation),
        "identity": {
            "capture_id": observation.capture_id,
            "phase": observation.phase,
            "batid_sha256": sha256(identity.batid.encode()).hexdigest(),
            "serial": identity.serial,
            "infoSize": identity.info_size,
            "mid": identity.mid,
            "type": identity.type,
            "using": identity.using,
        },
        "context": {
            "mower_state": observation.mower_state,
            "windows": list(observation.windows),
            "first_timestamp": observation.first_timestamp,
            "event_transports": list(observation.event_transports),
            "associated_control_transports": list(
                observation.associated_control_transports
            ),
            "associated_control_delta_microseconds": list(
                observation.associated_control_delta_microseconds
            ),
            "roles": list(observation.roles),
        },
        "segments": [
            {
                "index": item.index,
                "original_representation_length": item.original_representation_length,
                "original_representation_sha256": (item.original_representation_sha256),
                "derived_length": item.derived_byte_length,
                "derived_sha256": item.derived_sha256,
            }
            for item in segment_set.segments
        ],
        "structural_measurements": {
            "derived_total_length": len(raw),
            "derived_sha256": segment_set.derived_concatenation_sha256,
            "leading_bytes_hex": leading_preview.hex(),
            "leading_bytes_count": len(leading_preview),
            "trailing_zero_run_length": _trailing_zero_run(raw),
            "repeated_block_candidates": _repeated_block_candidates(raw),
            "known_magic_matches": _known_magic_matches(raw),
        },
    }


def _pairwise_comparisons(
    observations: Sequence[GroupedOnAriObservation],
    reports: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    result = []
    for left_index, right_index in combinations(range(len(observations)), 2):
        left = observations[left_index]
        right = observations[right_index]
        left_raw = left.segment_set.derived_concatenation
        right_raw = right.segment_set.derived_concatenation
        result.append(
            {
                "left_group_id": reports[left_index]["group_id"],
                "right_group_id": reports[right_index]["group_id"],
                "relations": _pair_relations(left, right),
                "left_length": len(left_raw),
                "right_length": len(right_raw),
                "length_change": len(right_raw) - len(left_raw),
                "common_prefix_bytes": _common_prefix(left_raw, right_raw),
                "common_suffix_bytes": _common_suffix(left_raw, right_raw),
                "first_differing_offset": _first_differing_offset(left_raw, right_raw),
                "identical_derived_bytes": left_raw == right_raw,
            }
        )
    return result


def _pair_relations(
    left: GroupedOnAriObservation,
    right: GroupedOnAriObservation,
) -> list[str]:
    relations = []
    left_identity = left.segment_set.identity
    right_identity = right.segment_set.identity
    if (
        left_identity.serial,
        left_identity.mid,
        left_identity.type,
        left_identity.using,
    ) == (
        right_identity.serial,
        right_identity.mid,
        right_identity.type,
        right_identity.using,
    ):
        relations.append("same-envelope-shape")
        if left.segment_set.derived_concatenation_length != (
            right.segment_set.derived_concatenation_length
        ):
            relations.append("same-envelope-shape-different-derived-length")
    if left.capture_id != right.capture_id:
        relations.append("different-capture")
    shared_roles = set(left.roles) & set(right.roles)
    if "request-associated" in shared_roles:
        relations.append("same-request-associated-role")
    if (
        "cadence-associated" in shared_roles
        and left_identity.serial == right_identity.serial == 1
    ):
        relations.append("cadence-associated-serial-one")
    controls = set(left.associated_control_transports) | set(
        right.associated_control_transports
    )
    if "legacy" in controls and "ngiot" in controls:
        relations.append("legacy-versus-ngiot")
        if left.capture_id == right.capture_id:
            relations.append("same-capture-legacy-versus-ngiot")
    return relations


def _explicit_control_markers(
    records: Sequence[VerifiedArtifactRecord],
) -> dict[str, VerifiedArtifactRecord]:
    markers: dict[str, VerifiedArtifactRecord] = {}
    for record in records:
        if (
            record.command == "getMI"
            and record.direction == "response"
            and record.transport in {"legacy", "ngiot"}
        ):
            markers[record.window] = record
    return markers


def _comparison_categories(
    comparisons: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for comparison in comparisons:
        for relation in comparison["relations"]:
            grouped[relation].append(comparison)
    return [
        {
            "relation": relation,
            "pair_count": len(items),
            "pairs": [
                {
                    "left_group_id": item["left_group_id"],
                    "right_group_id": item["right_group_id"],
                    "left_length": item["left_length"],
                    "right_length": item["right_length"],
                    "identical_derived_bytes": item["identical_derived_bytes"],
                }
                for item in items
            ],
        }
        for relation, items in sorted(grouped.items())
    ]


def _field_candidates(
    observations: Sequence[GroupedOnAriObservation],
) -> dict[str, Any]:
    scans = _integer_scans(observations)
    relations: tuple[
        tuple[
            str,
            Callable[[GroupedOnAriObservation, int], bool],
            Callable[[GroupedOnAriObservation], Any],
        ],
        ...,
    ] = (
        (
            "equals-envelope-infoSize",
            lambda item, value: (
                isinstance(item.segment_set.identity.info_size, int)
                and value == item.segment_set.identity.info_size
            ),
            lambda item: item.segment_set.identity.info_size,
        ),
        (
            "equals-envelope-serial",
            lambda item, value: value == item.segment_set.identity.serial,
            lambda item: item.segment_set.identity.serial,
        ),
        (
            "equals-derived-total-length",
            lambda item, value: value == item.segment_set.derived_concatenation_length,
            lambda item: item.segment_set.derived_concatenation_length,
        ),
        (
            "matches-envelope-index-set",
            lambda item, value: value in range(item.segment_set.identity.serial),
            lambda item: list(range(item.segment_set.identity.serial)),
        ),
    )
    return {
        "scan_scope": {
            "leading_bytes": _PREVIEW_BYTES,
            "integer_widths": list(_INTEGER_WIDTHS),
            "byte_orders": list(_BYTE_ORDERS),
            "unaligned_offsets_included": True,
        },
        "relations": [
            _relation_candidates(name, scans, observations, matcher, target)
            for name, matcher, target in relations
        ],
        "parser_boundary_adoption": "disabled-pending-independent-review",
    }


def _integer_scans(
    observations: Sequence[GroupedOnAriObservation],
) -> dict[tuple[int, int, str], dict[str, int]]:
    scans: dict[tuple[int, int, str], dict[str, int]] = defaultdict(dict)
    for observation in observations:
        group_id = _group_id(observation)
        raw = observation.segment_set.derived_concatenation
        limit = min(len(raw), _PREVIEW_BYTES)
        for width in _INTEGER_WIDTHS:
            for offset in range(max(0, limit - width + 1)):
                field = raw[offset : offset + width]
                for byte_order in _BYTE_ORDERS:
                    scans[(offset, width, byte_order)][group_id] = int.from_bytes(
                        field, byte_order
                    )
    return scans


def _relation_candidates(
    relation: str,
    scans: dict[tuple[int, int, str], dict[str, int]],
    observations: Sequence[GroupedOnAriObservation],
    matcher: Callable[[GroupedOnAriObservation, int], bool],
    target: Callable[[GroupedOnAriObservation], Any],
) -> dict[str, Any]:
    by_id = {_group_id(item): item for item in observations}
    assessments: list[dict[str, Any]] = []
    for (offset, width, byte_order), values in scans.items():
        supporting = []
        counterexamples = []
        for group_id, value in sorted(values.items()):
            item = by_id[group_id]
            example = {
                "group_id": group_id,
                "capture_id": item.capture_id,
                "timestamp": item.first_timestamp,
                "observed_value": value,
                "target_value": target(item),
            }
            if matcher(item, value):
                supporting.append(example)
            else:
                counterexamples.append(example)
        if len(supporting) < 2:
            continue
        distinct_observed = {item["observed_value"] for item in supporting}
        independent_captures = {item["capture_id"] for item in supporting}
        if counterexamples:
            status = "rejected"
        elif len(distinct_observed) >= 2 and len(independent_captures) >= 2:
            status = "supported"
        else:
            status = "candidate"
        assessments.append(
            {
                "field_id": f"offset-{offset}-width-{width}-{byte_order}",
                "offset": offset,
                "width": width,
                "byte_order": byte_order,
                "status": status,
                "observed_values": _observed_values(values),
                "supporting_examples": supporting,
                "counterexamples": counterexamples,
            }
        )
    assessments.sort(
        key=lambda item: (
            0 if item["status"] == "supported" else 1,
            len(item["counterexamples"]),
            -len(item["supporting_examples"]),
            item["offset"],
            item["width"],
            item["byte_order"],
        )
    )
    selected = assessments[:_MAX_REPORTED_FIELDS_PER_RELATION]
    if any(item["status"] == "supported" for item in selected):
        status = "supported"
    elif any(item["status"] == "candidate" for item in selected):
        status = "candidate"
    else:
        status = "rejected"
    return {
        "relation": relation,
        "status": status,
        "fields": selected,
        "supporting_group_requirement": 2,
        "independent_example_requirement_for_supported": 2,
    }


def _observed_values(values: dict[str, int]) -> list[dict[str, Any]]:
    grouped: dict[int, list[str]] = defaultdict(list)
    for group_id, value in values.items():
        grouped[value].append(group_id)
    return [
        {
            "value": value,
            "occurrence_count": len(group_ids),
            "group_ids": sorted(group_ids),
        }
        for value, group_ids in sorted(grouped.items())
    ]


def _common_across_all(
    observations: Sequence[GroupedOnAriObservation],
) -> dict[str, Any]:
    if not observations:
        return {
            "common_prefix_bytes": 0,
            "common_suffix_bytes": 0,
            "common_prefix_hex": "",
            "common_suffix_hex": "",
        }
    values = [item.segment_set.derived_concatenation for item in observations]
    prefix = values[0]
    suffix = values[0]
    for value in values[1:]:
        prefix = prefix[: _common_prefix(prefix, value)]
        suffix = suffix[len(suffix) - _common_suffix(suffix, value) :]
    return {
        "common_prefix_bytes": len(prefix),
        "common_suffix_bytes": len(suffix),
        "common_prefix_hex": _non_complete_preview(prefix).hex(),
        "common_suffix_hex": _non_complete_preview(suffix, from_end=True).hex(),
    }


def _repeated_block_candidates(raw: bytes) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for width in (4, 8, 16):
        positions: dict[bytes, list[int]] = defaultdict(list)
        for offset in range(len(raw) - width + 1):
            positions[raw[offset : offset + width]].append(offset)
        for value, offsets in positions.items():
            non_overlapping = _non_overlapping_offsets(offsets, width)
            if len(non_overlapping) < 3:
                continue
            candidates.append(
                {
                    "width": width,
                    "sha256": sha256(value).hexdigest(),
                    "occurrence_count": len(non_overlapping),
                    "offsets": non_overlapping[:16],
                    "all_zero": not any(value),
                }
            )
    candidates.sort(
        key=lambda item: (-item["width"], -item["occurrence_count"], item["sha256"])
    )
    return candidates[:12]


def _known_magic_matches(raw: bytes) -> list[dict[str, Any]]:
    inspected = raw[:_PREVIEW_BYTES]
    matches = []
    for name, magic in _KNOWN_MAGICS:
        offset = inspected.find(magic)
        if offset >= 0:
            matches.append({"name": name, "offset": offset})
    for offset in range(max(0, len(inspected) - 1)):
        first, second = inspected[offset : offset + 2]
        if first & 0x0F == 8 and (first << 8 | second) % 31 == 0:
            matches.append({"name": "zlib", "offset": offset})
    return matches


def _non_overlapping_offsets(offsets: Sequence[int], width: int) -> list[int]:
    selected = []
    next_offset = 0
    for offset in offsets:
        if offset < next_offset:
            continue
        selected.append(offset)
        next_offset = offset + width
    return selected


def _count_values(values: Any) -> list[dict[str, Any]]:
    counts: dict[Any, int] = defaultdict(int)
    for value in values:
        counts[value] += 1
    return [
        {"value": value, "count": count}
        for value, count in sorted(counts.items(), key=lambda item: repr(item[0]))
    ]


def _required_decimal_integer(record: VerifiedArtifactRecord, path: str) -> int:
    value = _required_scalar(record, path)
    try:
        return normalize_segment_cardinality(
            path,
            value,
            allow_zero=path.endswith(".index"),
        )
    except SegmentGroupingError as err:
        message = f"{path} is not a canonical decimal integer"
        raise OnAriFramingResearchError(message) from err


def _required_envelope_value(
    record: VerifiedArtifactRecord,
    path: str,
) -> EnvelopeValue:
    value = _required_scalar(record, path)
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        message = f"{path} is not an opaque scalar"
        raise OnAriFramingResearchError(message)
    return value


def _required_scalar(record: VerifiedArtifactRecord, path: str) -> Any:
    segment = _segment(record, path)
    if segment is not None:
        value = _segment_scalar(segment)
        if value is not None:
            return value
    value = _envelope_path(record.sanitized_envelope, path)
    if isinstance(value, str) and value.startswith("<redacted:"):
        value = None
    if value is None:
        message = f"Missing verified envelope value at {path}"
        raise OnAriFramingResearchError(message)
    return value


def _segment_scalar(segment: VerifiedOpaqueSegment) -> Any:
    if segment.kind == "json-string-utf8-value":
        try:
            return segment.raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if segment.kind == "canonical-json-v1":
        try:
            return orjson.loads(segment.raw)
        except orjson.JSONDecodeError:
            return None
    return None


def _segment(
    record: VerifiedArtifactRecord,
    source_path: str,
) -> VerifiedOpaqueSegment | None:
    return next(
        (item for item in record.opaque_segments if item.source_path == source_path),
        None,
    )


def _envelope_path(value: Any, path: str) -> Any:
    current = value
    for part in path.removeprefix("$.").split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _group_id(observation: GroupedOnAriObservation) -> str:
    identity = observation.segment_set.identity
    encoded = orjson.dumps(
        [
            observation.capture_id,
            identity.batid,
            identity.serial,
            identity.info_size,
            identity.mid,
            identity.type,
            identity.using,
        ]
    )
    return sha256(encoded).hexdigest()[:20]


def _identity_digest(capture_id: str, identity: tuple[Any, ...]) -> str:
    return sha256(orjson.dumps([capture_id, *identity])).hexdigest()


def _observation_sort_key(item: GroupedOnAriObservation) -> tuple[str, str, str]:
    return item.phase, item.first_timestamp, _group_id(item)


def _timestamp_delta_microseconds(before: str, after: str) -> int:
    delta = datetime.fromisoformat(after) - datetime.fromisoformat(before)
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def _common_prefix(left: bytes, right: bytes) -> int:
    count = 0
    for left_byte, right_byte in zip(left, right, strict=False):
        if left_byte != right_byte:
            break
        count += 1
    return count


def _common_suffix(left: bytes, right: bytes) -> int:
    count = 0
    for left_byte, right_byte in zip(reversed(left), reversed(right), strict=False):
        if left_byte != right_byte:
            break
        count += 1
    return count


def _first_differing_offset(left: bytes, right: bytes) -> int | None:
    prefix = _common_prefix(left, right)
    if left == right:
        return None
    return prefix


def _trailing_zero_run(raw: bytes) -> int:
    return len(raw) - len(raw.rstrip(b"\x00"))


def _non_complete_preview(raw: bytes, *, from_end: bool = False) -> bytes:
    """Return at most 64 bytes while never returning a complete non-empty value."""
    count = min(_PREVIEW_BYTES, max(0, len(raw) - 1))
    return raw[-count:] if from_end and count else raw[:count]
