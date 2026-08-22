"""Read-only structural burst analysis for opaque GOAT onArI observations."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from itertools import pairwise
from typing import TYPE_CHECKING, Any

import orjson

from .goat_map_delta import (
    ArtifactDeltaError,
    VerifiedArtifactRecord,
    VerifiedOpaqueSegment,
    VerifiedPhase2Artifact,
    load_verified_phase2_artifact,
)
from .goat_map_representation import (
    RepresentationDecodeError,
    decode_strict_base64_representation,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

_ANALYSIS_VERSION = "goat-onari-burst-framing/v1"
_INFO_PATH = "$.body.data.info"
_INFO_SIZE_PATH = "$.body.data.infoSize"
_MICROSECONDS_PER_SECOND = 1_000_000
_DEFAULT_BURST_THRESHOLD_MICROSECONDS = 250_000
_ON_MI_ASSOCIATION_MICROSECONDS = 2_000_000
_SEQUENCE_LIKE_NAMES = (
    "sequence",
    "serial",
    "index",
    "offset",
    "total",
    "chunk",
    "part",
    "count",
)
_MISSING = "<not-present>"


class OnAriAnalysisError(ValueError):
    """The immutable corpus cannot be analyzed safely or consistently."""


@dataclass(frozen=True, slots=True)
class _OnMiReference:
    timestamp: str
    delta_microseconds: int
    representation_length: int | None
    representation_sha256: str | None
    form: str


@dataclass(slots=True)
class _Occurrence:
    artifact: VerifiedPhase2Artifact
    record: VerifiedArtifactRecord
    info: VerifiedOpaqueSegment
    decoded: bytes | None
    base64_error: str | None
    envelope_fields: dict[str, Any]
    preceding_on_mi: _OnMiReference | None
    burst_id: str = ""
    burst_ordinal: int = 0


def analyze_on_ari_corpus(
    artifact_dirs: Sequence[Path],
    *,
    burst_threshold_microseconds: int = _DEFAULT_BURST_THRESHOLD_MICROSECONDS,
) -> dict[str, Any]:
    """Analyze onArI timing/framing without modifying artifacts or parsing maps."""
    if not artifact_dirs:
        raise OnAriAnalysisError("At least one Phase 2 artifact is required")
    if not 1_000 <= burst_threshold_microseconds <= 2_000_000:
        raise OnAriAnalysisError("Burst threshold must be 1000--2000000 microseconds")
    try:
        artifacts = sorted(
            (load_verified_phase2_artifact(path) for path in artifact_dirs),
            key=lambda item: item.phase,
        )
    except ArtifactDeltaError as err:
        raise OnAriAnalysisError(str(err)) from err
    capture_ids = [artifact.capture_id for artifact in artifacts]
    if len(capture_ids) != len(set(capture_ids)):
        raise OnAriAnalysisError("Corpus contains duplicate capture IDs")

    occurrences = _collect_occurrences(artifacts)
    bursts = _assign_bursts(
        occurrences,
        threshold_microseconds=burst_threshold_microseconds,
    )
    burst_reports = [_burst_report(burst) for burst in bursts]
    occurrence_reports = [_occurrence_report(item) for item in occurrences]
    invalid = [item for item in occurrence_reports if not item["strict_base64_valid"]]
    return {
        "schema_version": "goat-onari-burst-framing-report/v1",
        "analysis_version": _ANALYSIS_VERSION,
        "analysis_kind": "opaque-read-only-onari-burst-framing",
        "semantic_map_decoding": False,
        "chunk_reassembler_implemented": False,
        "framing_parser_implemented": False,
        "artifact_modification": False,
        "timing_basis": {
            "unit": "integer-microseconds",
            "burst_threshold_microseconds": burst_threshold_microseconds,
            "on_mi_association_threshold_microseconds": (
                _ON_MI_ASSOCIATION_MICROSECONDS
            ),
        },
        "corpus": {
            "capture_count": len(artifacts),
            "on_ari_occurrence_count": len(occurrences),
            "burst_count": len(bursts),
            "single_message_burst_count": sum(len(item) == 1 for item in bursts),
            "multi_message_burst_count": sum(len(item) > 1 for item in bursts),
            "captures": [
                {
                    "capture_id": item.capture_id,
                    "phase": item.phase,
                    "mower_state": item.mower_state,
                }
                for item in artifacts
            ],
        },
        "strict_base64_assessment": {
            "valid_count": len(occurrences) - len(invalid),
            "invalid_count": len(invalid),
            "corpus_result": (
                "all-observed-onArI-info-pass-strict-canonical-base64"
                if occurrences and not invalid
                else "not-established-for-entire-corpus"
            ),
            "invalid_observations": invalid,
        },
        "occurrences": occurrence_reports,
        "bursts": burst_reports,
        "burst_patterns": _burst_patterns(burst_reports),
        "target_pattern_comparison": _target_pattern_comparison(burst_reports),
        "fixture_assessment": _fixture_assessment(artifacts, occurrence_reports),
        "negative_findings": _negative_findings(occurrences, burst_reports),
        "interpretation_guard": (
            "Burst proximity, ordinal order, envelope names, Base64-derived bytes, "
            "concatenation, lengths, digests, and signatures are structural evidence "
            "only. No result is a chunk reconstruction or semantic map record."
        ),
    }


def _collect_occurrences(
    artifacts: Sequence[VerifiedPhase2Artifact],
) -> list[_Occurrence]:
    occurrences: list[_Occurrence] = []
    for artifact in artifacts:
        preceding_on_mi: VerifiedArtifactRecord | None = None
        for record in artifact.records:
            if record.command == "onMI" and record.direction == "event":
                preceding_on_mi = record
                continue
            if record.command != "onArI" or record.direction != "event":
                continue
            info = _segment(record, _INFO_PATH)
            if info is None:
                continue
            decoded = None
            base64_error = None
            try:
                decoded = decode_strict_base64_representation(info.raw.decode("ascii"))
            except (RepresentationDecodeError, UnicodeDecodeError) as err:
                base64_error = type(err).__name__
            occurrences.append(
                _Occurrence(
                    artifact=artifact,
                    record=record,
                    info=info,
                    decoded=decoded,
                    base64_error=base64_error,
                    envelope_fields=_envelope_fields(record),
                    preceding_on_mi=_on_mi_reference(record, preceding_on_mi),
                )
            )
    return occurrences


def _assign_bursts(
    occurrences: list[_Occurrence],
    *,
    threshold_microseconds: int,
) -> list[list[_Occurrence]]:
    by_capture: dict[str, list[_Occurrence]] = defaultdict(list)
    for occurrence in occurrences:
        by_capture[occurrence.artifact.capture_id].append(occurrence)
    bursts: list[list[_Occurrence]] = []
    for capture_id, capture_items in sorted(by_capture.items()):
        ordered = sorted(capture_items, key=lambda item: item.record.sequence)
        capture_bursts: list[list[_Occurrence]] = []
        for occurrence in ordered:
            if not capture_bursts:
                capture_bursts.append([occurrence])
                continue
            gap = _timestamp_delta_microseconds(
                capture_bursts[-1][-1].record.observed_at,
                occurrence.record.observed_at,
            )
            if gap <= threshold_microseconds:
                capture_bursts[-1].append(occurrence)
            else:
                capture_bursts.append([occurrence])
        for number, burst in enumerate(capture_bursts, start=1):
            burst_id = f"{capture_id[:12]}-ari-{number:03d}"
            for ordinal, occurrence in enumerate(burst, start=1):
                occurrence.burst_id = burst_id
                occurrence.burst_ordinal = ordinal
            bursts.append(burst)
    return bursts


def _occurrence_report(item: _Occurrence) -> dict[str, Any]:
    decoded = item.decoded
    preceding = item.preceding_on_mi
    return {
        "capture_id": item.artifact.capture_id,
        "phase": item.artifact.phase,
        "mower_state": item.record.mower_state,
        "window": item.record.window,
        "timestamp": item.record.observed_at,
        "sequence": item.record.sequence,
        "transport": item.record.transport,
        "burst_id": item.burst_id,
        "burst_ordinal": item.burst_ordinal,
        "mid": item.envelope_fields.get("$.body.data.mid"),
        "aid": item.envelope_fields.get("$.body.data.aid"),
        "type": item.envelope_fields.get("$.body.data.type"),
        "infoSize": item.envelope_fields.get(_INFO_SIZE_PATH),
        "envelope_fields": item.envelope_fields,
        "original_representation_length": len(item.info.raw),
        "original_representation_sha256": item.info.sha256,
        "strict_base64_valid": decoded is not None,
        "strict_base64_error": item.base64_error,
        "decoded_length": len(decoded) if decoded is not None else None,
        "decoded_sha256": sha256(decoded).hexdigest() if decoded is not None else None,
        "decoded_leading_bytes_hex": decoded[:8].hex() if decoded is not None else None,
        "decoded_trailing_bytes_hex": decoded[-8:].hex()
        if decoded is not None
        else None,
        "decoded_known_signatures": _known_signatures(decoded)
        if decoded is not None
        else [],
        "preceding_on_mi": (
            {
                "timestamp": preceding.timestamp,
                "delta_microseconds": preceding.delta_microseconds,
                "delta_seconds": preceding.delta_microseconds
                / _MICROSECONDS_PER_SECOND,
                "within_association_threshold": (
                    preceding.delta_microseconds <= _ON_MI_ASSOCIATION_MICROSECONDS
                ),
                "representation_length": preceding.representation_length,
                "representation_sha256": preceding.representation_sha256,
                "form": preceding.form,
            }
            if preceding is not None
            else None
        ),
    }


def _burst_report(burst: list[_Occurrence]) -> dict[str, Any]:
    reports = [_occurrence_report(item) for item in burst]
    envelope = _compare_envelopes(reports)
    valid = all(item.decoded is not None for item in burst)
    representation_concat = b"".join(item.info.raw for item in burst)
    decoded_concat = b"".join(item.decoded or b"" for item in burst) if valid else None
    strict_concat = None
    if valid:
        try:
            strict_concat = decode_strict_base64_representation(
                representation_concat.decode("ascii")
            )
        except RepresentationDecodeError, UnicodeDecodeError:
            strict_concat = None
    info_sizes = _integer_values(
        item.envelope_fields.get(_INFO_SIZE_PATH) for item in burst
    )
    representation_total = len(representation_concat)
    decoded_total = len(decoded_concat) if decoded_concat is not None else None
    first = reports[0]
    return {
        "burst_id": burst[0].burst_id,
        "capture_id": burst[0].artifact.capture_id,
        "phase": burst[0].artifact.phase,
        "window": burst[0].record.window,
        "mower_state": burst[0].record.mower_state,
        "first_timestamp": burst[0].record.observed_at,
        "last_timestamp": burst[-1].record.observed_at,
        "span_microseconds": _timestamp_delta_microseconds(
            burst[0].record.observed_at,
            burst[-1].record.observed_at,
        ),
        "message_count": len(burst),
        "associated_on_mi_form": (
            first["preceding_on_mi"]["form"]
            if first["preceding_on_mi"] is not None
            and first["preceding_on_mi"]["within_association_threshold"]
            else "unassociated"
        ),
        "associated_on_mi_consistent": len(
            {
                (
                    item["preceding_on_mi"]["timestamp"],
                    item["preceding_on_mi"]["form"],
                )
                for item in reports
                if item["preceding_on_mi"] is not None
            }
        )
        <= 1,
        "associated_on_mi_reference_count": len(
            {
                item["preceding_on_mi"]["timestamp"]
                for item in reports
                if item["preceding_on_mi"] is not None
            }
        ),
        "proximity_group_contains_multiple_on_mi": len(
            {
                item["preceding_on_mi"]["timestamp"]
                for item in reports
                if item["preceding_on_mi"] is not None
            }
        )
        > 1,
        "structural_boundary_candidates": _structural_boundary_candidates(reports),
        "representation_lengths": [
            item["original_representation_length"] for item in reports
        ],
        "decoded_lengths": [item["decoded_length"] for item in reports],
        "strict_base64_all_valid": valid,
        "first_representation_exactly_1024": (
            reports[0]["original_representation_length"] == 1024
        ),
        "first_1024_decodes_to_768": (
            reports[0]["original_representation_length"] == 1024
            and reports[0]["decoded_length"] == 768
        ),
        "envelope_comparison": envelope,
        "sequence_like_fields_by_name": [
            item for item in envelope if _sequence_like_field(item["field"])
        ],
        "structural_concatenation_candidate": {
            "performed": valid,
            "not_a_reconstruction": True,
            "representation_total_length": representation_total,
            "representation_concat_sha256": sha256(representation_concat).hexdigest(),
            "concatenated_representation_is_strict_base64": strict_concat is not None,
            "decoded_parts_total_length": decoded_total,
            "decoded_parts_concat_sha256": (
                sha256(decoded_concat).hexdigest()
                if decoded_concat is not None
                else None
            ),
            "strict_representation_decode_matches_decoded_parts": (
                strict_concat == decoded_concat
                if strict_concat is not None and decoded_concat is not None
                else None
            ),
            "decoded_concat_leading_bytes_hex": (
                decoded_concat[:8].hex() if decoded_concat is not None else None
            ),
            "decoded_concat_trailing_bytes_hex": (
                decoded_concat[-8:].hex() if decoded_concat is not None else None
            ),
            "decoded_concat_known_signatures": (
                _known_signatures(decoded_concat) if decoded_concat is not None else []
            ),
        },
        "infoSize_relationship": {
            "observed_values": info_sizes,
            "same_value_across_burst": len(info_sizes) == 1,
            "representation_total_length": representation_total,
            "decoded_total_length": decoded_total,
            "comparisons": [
                {
                    "infoSize": value,
                    "equals_representation_total": value == representation_total,
                    "equals_decoded_total": value == decoded_total,
                    "minus_representation_total": value - representation_total,
                    "minus_decoded_total": (
                        value - decoded_total if decoded_total is not None else None
                    ),
                }
                for value in info_sizes
            ],
            "semantic_interpretation": False,
        },
        "messages": reports,
    }


def _compare_envelopes(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = sorted(
        {field for report in reports for field in report["envelope_fields"]}
    )
    comparison = []
    for field in fields:
        values = [report["envelope_fields"].get(field, _MISSING) for report in reports]
        unique = _stable_unique(values)
        status = (
            "redacted-not-comparable"
            if all(_is_redacted(value) for value in values)
            else "identical"
            if len(unique) == 1
            else "value-varies"
        )
        comparison.append(
            {
                "field": field,
                "status": status,
                "values_by_ordinal": values,
                "unique_values": unique,
            }
        )
    return comparison


def _structural_boundary_candidates(
    reports: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates = []
    for before, after in pairwise(reports):
        reasons = []
        before_on_mi = before["preceding_on_mi"]
        after_on_mi = after["preceding_on_mi"]
        if (
            before_on_mi is not None
            and after_on_mi is not None
            and before_on_mi["timestamp"] != after_on_mi["timestamp"]
        ):
            reasons.append("preceding-onMI-changed")
        before_fields = before["envelope_fields"]
        after_fields = after["envelope_fields"]
        if before_fields.get("$.body.data.batid") != after_fields.get(
            "$.body.data.batid"
        ):
            reasons.append("batid-value-changed")
        if (
            before_fields.get("$.body.data.index") != "0"
            and after_fields.get("$.body.data.index") == "0"
        ):
            reasons.append("observed-index-returned-to-zero")
        if reasons:
            candidates.append(
                {
                    "before_ordinal": before["burst_ordinal"],
                    "after_ordinal": after["burst_ordinal"],
                    "observed_reasons": reasons,
                    "semantic_boundary_proven": False,
                }
            )
    return candidates


def _burst_patterns(bursts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for burst in bursts:
        grouped[
            (
                burst["associated_on_mi_form"],
                tuple(burst["representation_lengths"]),
                tuple(burst["decoded_lengths"]),
                tuple(
                    (item["field"], item["status"])
                    for item in burst["envelope_comparison"]
                ),
            )
        ].append(burst)
    return [
        {
            "associated_on_mi_form": key[0],
            "representation_lengths": list(key[1]),
            "decoded_lengths": list(key[2]),
            "envelope_structure": [
                {"field": field, "status": status} for field, status in key[3]
            ],
            "occurrence_count": len(items),
            "capture_count": len({item["capture_id"] for item in items}),
            "burst_ids": [item["burst_id"] for item in items],
        }
        for key, items in sorted(grouped.items(), key=lambda item: repr(item[0]))
    ]


def _target_pattern_comparison(bursts: list[dict[str, Any]]) -> dict[str, Any]:
    pattern_872 = [
        item for item in bursts if item["representation_lengths"] == [1024, 872]
    ]
    pattern_896 = [
        item for item in bursts if item["representation_lengths"] == [1024, 896]
    ]
    cadence = [
        item
        for item in bursts
        if item["associated_on_mi_form"] == "cadence-associated form"
    ]
    request = [
        item
        for item in bursts
        if item["associated_on_mi_form"] == "request-associated form"
    ]
    return {
        "request_1024_plus_872": _pattern_evidence(pattern_872),
        "request_1024_plus_896": _pattern_evidence(pattern_896),
        "same_envelope_structure_872_vs_896": _same_envelope_structure(
            pattern_872,
            pattern_896,
        ),
        "request_associated_bursts": _structure_summary(request),
        "cadence_associated_bursts": _structure_summary(cadence),
        "structural_conclusion_only": True,
    }


def _pattern_evidence(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "burst_count": len(items),
        "capture_count": len({item["capture_id"] for item in items}),
        "all_first_1024_decode_to_768": bool(items)
        and all(item["first_1024_decodes_to_768"] for item in items),
        "burst_ids": [item["burst_id"] for item in items],
        "envelope_structures": [
            [
                {"field": field["field"], "status": field["status"]}
                for field in item["envelope_comparison"]
            ]
            for item in items
        ],
    }


def _same_envelope_structure(
    left: list[dict[str, Any]],
    right: list[dict[str, Any]],
) -> bool | None:
    if not left or not right:
        return None
    left_structures = {
        tuple(
            (field["field"], field["status"]) for field in item["envelope_comparison"]
        )
        for item in left
    }
    right_structures = {
        tuple(
            (field["field"], field["status"]) for field in item["envelope_comparison"]
        )
        for item in right
    }
    return left_structures == right_structures


def _structure_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "burst_count": len(items),
        "message_count_distribution": [
            {"message_count": message_count, "burst_count": burst_count}
            for message_count, burst_count in sorted(
                Counter(item["message_count"] for item in items).items()
            )
        ],
        "representation_length_patterns": [
            {"lengths": list(pattern), "count": count}
            for pattern, count in sorted(
                Counter(tuple(item["representation_lengths"]) for item in items).items()
            )
        ],
    }


def _fixture_assessment(
    artifacts: Sequence[VerifiedPhase2Artifact],
    on_ari: list[dict[str, Any]],
) -> dict[str, Any]:
    grouped: dict[tuple[str, str, int], list[tuple[str, str]]] = defaultdict(list)
    for artifact in artifacts:
        for record in artifact.records:
            for segment in record.opaque_segments:
                if (record.command == "onMI" and segment.source_path == _INFO_PATH) or (
                    record.command == "getAreaSet"
                    and segment.source_path == "$.body.data.subsets"
                ):
                    grouped[(record.command, segment.sha256, len(segment.raw))].append(
                        (artifact.capture_id, record.window)
                    )
    strong = []
    for (command, digest, length), contexts in sorted(grouped.items()):
        captures = {capture for capture, _ in contexts}
        windows = {window for _, window in contexts}
        if len(contexts) < 2 or len(captures) < 2 or len(windows) < 2:
            continue
        strong.append(
            {
                "command": command,
                "source_path": (
                    _INFO_PATH if command == "onMI" else "$.body.data.subsets"
                ),
                "representation_length": length,
                "representation_sha256": digest,
                "occurrence_count": len(contexts),
                "capture_count": len(captures),
                "status": "strong-golden-fixture-candidate-after-manual-review",
            }
        )
    ari_groups = Counter(
        (
            item["original_representation_sha256"],
            item["original_representation_length"],
        )
        for item in on_ari
    )
    return {
        "strong_opaque_candidates": strong,
        "on_ari_structural_examples": [
            {
                "representation_sha256": digest,
                "representation_length": length,
                "occurrence_count": count,
                "status": "structural-example-only-not-canonical",
            }
            for (digest, length), count in sorted(ari_groups.items())
        ],
        "opaque_bytes_added_to_repository": False,
    }


def _negative_findings(
    occurrences: list[_Occurrence],
    bursts: list[dict[str, Any]],
) -> list[str]:
    findings = []
    if not occurrences:
        findings.append("No onArI.info observations were present.")
    if any(item.decoded is None for item in occurrences):
        findings.append("At least one onArI.info failed strict canonical Base64.")
    if not any(item["message_count"] > 1 for item in bursts):
        findings.append("No multi-message onArI burst was observed.")
    if bursts and not any(
        item["structural_concatenation_candidate"]["decoded_concat_known_signatures"]
        for item in bursts
    ):
        findings.append(
            "No tested decoded-part concatenation begins with a known compression signature."
        )
    return findings


def _on_mi_reference(
    on_ari: VerifiedArtifactRecord,
    on_mi: VerifiedArtifactRecord | None,
) -> _OnMiReference | None:
    if on_mi is None:
        return None
    info = _segment(on_mi, _INFO_PATH)
    length = len(info.raw) if info is not None else None
    if length == 876:
        form = "request-associated form"
    elif length == 52:
        form = "cadence-associated form"
    else:
        form = "unclassified form"
    return _OnMiReference(
        timestamp=on_mi.observed_at,
        delta_microseconds=_timestamp_delta_microseconds(
            on_mi.observed_at,
            on_ari.observed_at,
        ),
        representation_length=length,
        representation_sha256=info.sha256 if info is not None else None,
        form=form,
    )


def _envelope_fields(record: VerifiedArtifactRecord) -> dict[str, Any]:
    result: dict[str, Any] = {}
    _flatten_envelope(record.sanitized_envelope, "$", result)
    result.pop(_INFO_PATH, None)
    for segment in record.opaque_segments:
        if segment.source_path == _INFO_PATH:
            continue
        scalar = _segment_scalar(segment)
        if scalar is not None:
            result[segment.source_path] = scalar
    return dict(sorted(result.items()))


def _flatten_envelope(value: Any, path: str, result: dict[str, Any]) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            _flatten_envelope(item, f"{path}.{key}", result)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _flatten_envelope(item, f"{path}[{index}]", result)
    else:
        result[path] = value


def _segment_scalar(segment: VerifiedOpaqueSegment) -> Any:
    try:
        value = orjson.loads(segment.raw)
    except orjson.JSONDecodeError:
        try:
            value = segment.raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return (
        value if isinstance(value, (str, int, float, bool)) or value is None else None
    )


def _segment(
    record: VerifiedArtifactRecord,
    source_path: str,
) -> VerifiedOpaqueSegment | None:
    return next(
        (item for item in record.opaque_segments if item.source_path == source_path),
        None,
    )


def _known_signatures(raw: bytes) -> list[str]:
    signatures = [
        name
        for name, prefix in (
            ("gzip", b"\x1f\x8b"),
            ("zip", b"PK\x03\x04"),
            ("bzip2", b"BZh"),
            ("xz", b"\xfd7zXZ\x00"),
            ("zstd", b"\x28\xb5\x2f\xfd"),
            ("lz4-frame", b"\x04\x22\x4d\x18"),
        )
        if raw.startswith(prefix)
    ]
    if len(raw) >= 2 and raw[0] & 0x0F == 8 and (raw[0] << 8 | raw[1]) % 31 == 0:
        signatures.append("zlib")
    return signatures


def _timestamp_delta_microseconds(before: str, after: str) -> int:
    delta = datetime.fromisoformat(after) - datetime.fromisoformat(before)
    return _duration_microseconds(delta)


def _duration_microseconds(value: timedelta) -> int:
    return (
        value.days * 86_400 * _MICROSECONDS_PER_SECOND
        + value.seconds * _MICROSECONDS_PER_SECOND
        + value.microseconds
    )


def _integer_values(values: Any) -> list[int]:
    return sorted(
        {
            value
            for value in values
            if isinstance(value, int) and not isinstance(value, bool)
        }
    )


def _stable_unique(values: list[Any]) -> list[Any]:
    result = []
    markers = set()
    for value in values:
        marker = orjson.dumps(value, option=orjson.OPT_SORT_KEYS)
        if marker in markers:
            continue
        markers.add(marker)
        result.append(value)
    return result


def _is_redacted(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("<redacted:")


def _sequence_like_field(path: str) -> bool:
    name = path.rsplit(".", maxsplit=1)[-1].casefold()
    return any(candidate in name for candidate in _SEQUENCE_LIKE_NAMES)
