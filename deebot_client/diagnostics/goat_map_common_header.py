"""Read-only common-header research across opaque onMI and onArI values."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
from typing import TYPE_CHECKING, Any, Literal

import orjson

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
    from collections.abc import Callable, Sequence
    from pathlib import Path

type MessageFamily = Literal["onMI", "onArI"]
type Association = Literal["request-associated", "cadence-associated", "unclassified"]
type ByteOrder = Literal["little", "big"]

_ANALYSIS_VERSION = "goat-cross-family-common-header/v1"
_INFO_PATH = "$.body.data.info"
_COLUMN_LIMIT = 64
_INFO_SIZE_OFFSET = 5
_FAMILY_SCAN_START = 9
_INTEGER_WIDTHS = (2, 4)
_BYTE_ORDERS: tuple[ByteOrder, ...] = ("little", "big")


class CommonHeaderResearchError(ValueError):
    """The immutable corpus cannot be analyzed safely or consistently."""


@dataclass(frozen=True, slots=True)
class CommonHeaderSample:
    """One uninterpreted derived value with observable structural metadata."""

    capture_id: str
    phase: str
    timestamp: str
    message_family: MessageFamily
    association: Association
    info_size: int
    derived_bytes: bytes
    derived_sha256: str


def analyze_cross_family_common_header_corpus(
    artifact_dirs: Sequence[Path],
) -> dict[str, Any]:
    """Verify artifacts and compare stable onMI forms with grouped onArI."""
    if not artifact_dirs:
        raise CommonHeaderResearchError("At least one Phase 2 artifact is required")
    try:
        artifacts = sorted(
            (load_verified_phase2_artifact(path) for path in artifact_dirs),
            key=lambda item: (item.phase, item.capture_id),
        )
    except ArtifactDeltaError as err:
        raise CommonHeaderResearchError(str(err)) from err
    capture_ids = [artifact.capture_id for artifact in artifacts]
    if len(capture_ids) != len(set(capture_ids)):
        raise CommonHeaderResearchError("Corpus contains duplicate capture IDs")

    samples, exclusions = collect_common_header_samples(artifacts)
    report = analyze_common_header_samples(samples)
    report["corpus"]["captures"] = [
        {
            "capture_id": artifact.capture_id,
            "phase": artifact.phase,
            "mower_state": artifact.mower_state,
        }
        for artifact in artifacts
    ]
    report["corpus"]["excluded_samples"] = exclusions
    report["corpus"]["excluded_sample_count"] = len(exclusions)
    return report


def collect_common_header_samples(
    artifacts: Sequence[VerifiedPhase2Artifact],
) -> tuple[list[CommonHeaderSample], list[dict[str, Any]]]:
    """Collect only proven onMI forms and complete grouped onArI streams."""
    samples: list[CommonHeaderSample] = []
    exclusions: list[dict[str, Any]] = []
    for artifact in artifacts:
        for record in artifact.records:
            if record.command != "onMI" or record.direction != "event":
                continue
            info = _segment(record, _INFO_PATH)
            if info is None or len(info.raw) not in {52, 876}:
                exclusions.append(
                    {
                        "capture_id": artifact.capture_id,
                        "sequence": record.sequence,
                        "family": "onMI",
                        "reason": "not-one-of-two-stable-representation-lengths",
                    }
                )
                continue
            try:
                derived = decode_strict_base64_representation(info.raw.decode("ascii"))
                info_size = _required_integer(record, "$.body.data.infoSize")
            except (
                CommonHeaderResearchError,
                RepresentationDecodeError,
                UnicodeDecodeError,
            ) as err:
                exclusions.append(
                    {
                        "capture_id": artifact.capture_id,
                        "sequence": record.sequence,
                        "family": "onMI",
                        "reason": type(err).__name__,
                    }
                )
                continue
            association: Association = (
                "request-associated" if len(info.raw) == 876 else "cadence-associated"
            )
            samples.append(
                CommonHeaderSample(
                    capture_id=artifact.capture_id,
                    phase=artifact.phase,
                    timestamp=record.observed_at,
                    message_family="onMI",
                    association=association,
                    info_size=info_size,
                    derived_bytes=derived,
                    derived_sha256=sha256(derived).hexdigest(),
                )
            )

    on_ari, grouped_exclusions = collect_grouped_on_ari_observations(artifacts)
    exclusions.extend(grouped_exclusions)
    for observation in on_ari:
        identity = observation.segment_set.identity
        if not isinstance(identity.info_size, int):
            exclusions.append(
                {
                    "capture_id": observation.capture_id,
                    "family": "onArI",
                    "reason": "infoSize-is-not-an-integer",
                }
            )
            continue
        association = _association(observation.roles)
        samples.append(
            CommonHeaderSample(
                capture_id=observation.capture_id,
                phase=observation.phase,
                timestamp=observation.first_timestamp,
                message_family="onArI",
                association=association,
                info_size=identity.info_size,
                derived_bytes=observation.segment_set.derived_concatenation,
                derived_sha256=(observation.segment_set.derived_concatenation_sha256),
            )
        )
    return samples, exclusions


def analyze_common_header_samples(
    samples: Sequence[CommonHeaderSample],
) -> dict[str, Any]:
    """Build deterministic metadata-only common-header evidence."""
    if not samples:
        raise CommonHeaderResearchError("At least one derived sample is required")
    ordered = sorted(samples, key=_sample_sort_key)
    if any(not item.derived_bytes for item in ordered):
        raise CommonHeaderResearchError("Derived samples must not be empty")
    sample_reports = [_sample_report(item) for item in ordered]
    columns = [_column_report(ordered, offset) for offset in range(_COLUMN_LIMIT)]
    info_size_hypotheses = _info_size_hypotheses(ordered)
    invariant = _shared_invariant_run(ordered)
    family = _metadata_relation(
        ordered, "message-family", lambda item: item.message_family
    )
    association = _metadata_relation(
        ordered,
        "association",
        lambda item: item.association,
    )
    total_length = _integer_relation_scan(
        ordered,
        "equals-derived-total-length",
        lambda item: len(item.derived_bytes),
        scan_start=7,
    )
    return {
        "schema_version": "goat-cross-family-common-header-report/v1",
        "analysis_version": _ANALYSIS_VERSION,
        "analysis_kind": "opaque-read-only-cross-family-common-header",
        "artifact_modification": False,
        "parser_implemented": False,
        "decoder_implemented": False,
        "opaque_full_values_in_report": False,
        "corpus": {
            "sample_count": len(ordered),
            "capture_count": len({item.capture_id for item in ordered}),
            "message_family_distribution": _distribution(
                item.message_family for item in ordered
            ),
            "association_distribution": _distribution(
                item.association for item in ordered
            ),
            "onMI_stable_forms": _on_mi_forms(ordered),
        },
        "samples": sample_reports,
        "longest_common_prefix": {
            "entire_corpus": _prefix_report(ordered),
            "by_message_family": [
                {
                    "message_family": family_name,
                    **_prefix_report(
                        [item for item in ordered if item.message_family == family_name]
                    ),
                }
                for family_name in ("onMI", "onArI")
            ],
        },
        "byte_column_inventory": columns,
        "field_candidates": {
            "infoSize_width_hypotheses": info_size_hypotheses,
            "unknown_after_uint16_infoSize": _zero_only_candidate(ordered),
            "shared_invariant_after_infoSize": invariant,
            "message_family_relation": family,
            "association_relation": association,
            "derived_total_length_relation": total_length,
        },
        "first_post_infoSize_structure_change": _first_structure_change(
            ordered,
            invariant,
            family,
        ),
        "interpretation_guard": (
            "Byte columns, offsets, invariant runs, integer readings, and metadata "
            "relations are structural observations only. No candidate is consumed "
            "as a parsed field."
        ),
    }


def _sample_report(item: CommonHeaderSample) -> dict[str, Any]:
    return {
        "sample_id": _sample_id(item),
        "capture_id": item.capture_id,
        "phase": item.phase,
        "timestamp": item.timestamp,
        "message_family": item.message_family,
        "association": item.association,
        "infoSize": item.info_size,
        "derived_total_length": len(item.derived_bytes),
        "derived_sha256": item.derived_sha256,
    }


def _column_report(
    samples: Sequence[CommonHeaderSample],
    offset: int,
) -> dict[str, Any]:
    present = [item for item in samples if len(item.derived_bytes) > offset]
    values = _column_values(present, offset)
    return {
        "offset": offset,
        "sample_count": len(present),
        "missing_sample_count": len(samples) - len(present),
        "stability": _column_stability(values, len(present), len(samples)),
        "values": values,
        "by_message_family": _column_groups(
            present,
            offset,
            lambda item: item.message_family,
            "message_family",
        ),
        "by_association": _column_groups(
            present,
            offset,
            lambda item: item.association,
            "association",
        ),
        "by_infoSize": _column_groups(
            present,
            offset,
            lambda item: item.info_size,
            "infoSize",
        ),
    }


def _column_groups(
    samples: Sequence[CommonHeaderSample],
    offset: int,
    key: Callable[[CommonHeaderSample], Any],
    key_name: str,
) -> list[dict[str, Any]]:
    grouped: dict[Any, list[CommonHeaderSample]] = defaultdict(list)
    for sample in samples:
        grouped[key(sample)].append(sample)
    return [
        {
            key_name: group,
            "sample_count": len(items),
            "capture_count": len({item.capture_id for item in items}),
            "stability": _column_stability(
                _column_values(items, offset), len(items), len(items)
            ),
            "values": _column_values(items, offset),
        }
        for group, items in sorted(grouped.items(), key=lambda item: repr(item[0]))
    ]


def _column_values(
    samples: Sequence[CommonHeaderSample],
    offset: int,
) -> list[dict[str, Any]]:
    grouped: dict[int, list[CommonHeaderSample]] = defaultdict(list)
    for sample in samples:
        grouped[sample.derived_bytes[offset]].append(sample)
    return [
        {
            "value": value,
            "hex": f"{value:02x}",
            "occurrence_count": len(items),
            "capture_count": len({item.capture_id for item in items}),
            "sample_ids": sorted(_sample_id(item) for item in items),
        }
        for value, items in sorted(grouped.items())
    ]


def _column_stability(
    values: Sequence[dict[str, Any]],
    present_count: int,
    total_count: int,
) -> str:
    if not present_count:
        return "not-observed"
    if len(values) == 1 and present_count == total_count:
        return "constant"
    if len(values) == 1:
        return "constant-among-present"
    return "variable"


def _info_size_hypotheses(
    samples: Sequence[CommonHeaderSample],
) -> dict[str, Any]:
    uint16 = _exact_integer_candidate(
        samples,
        candidate_id="offset-5-uint16-little",
        offset=_INFO_SIZE_OFFSET,
        width=2,
        byte_order="little",
        target=lambda item: item.info_size,
    )
    uint32 = _exact_integer_candidate(
        samples,
        candidate_id="offset-5-uint32-little",
        offset=_INFO_SIZE_OFFSET,
        width=4,
        byte_order="little",
        target=lambda item: item.info_size,
    )
    return {
        "uint16_little": uint16,
        "uint32_little": uint32,
        "width_discrimination": {
            "status": "candidate",
            "selected_width": None,
            "reason": (
                "Both widths match every sample because bytes 7-8 are zero and all "
                "observed infoSize values fit in 16 bits."
            ),
            "counterexamples": [],
        },
    }


def _zero_only_candidate(samples: Sequence[CommonHeaderSample]) -> dict[str, Any]:
    supporting = [_example(item, 0, 0) for item in samples]
    counterexamples = [
        _example(
            item,
            int.from_bytes(item.derived_bytes[7:9], "little"),
            0,
        )
        for item in samples
        if len(item.derived_bytes) < 9
        or int.from_bytes(item.derived_bytes[7:9], "little") != 0
    ]
    status = "rejected" if counterexamples else "candidate"
    return {
        "candidate_id": "offset-7-width-2-unknown",
        "offset": 7,
        "width": 2,
        "status": status,
        "observed_values": [0] if not counterexamples else [],
        "supporting_examples": supporting if not counterexamples else [],
        "counterexamples": counterexamples,
        "support_limit": "zero-only-with-no-varying-metadata-relation",
    }


def _shared_invariant_run(
    samples: Sequence[CommonHeaderSample],
) -> dict[str, Any]:
    offset = 9
    values: list[int] = []
    while offset + len(values) < _COLUMN_LIMIT:
        column_offset = offset + len(values)
        if any(len(item.derived_bytes) <= column_offset for item in samples):
            break
        column = {item.derived_bytes[column_offset] for item in samples}
        if len(column) != 1:
            break
        values.append(next(iter(column)))
    raw = bytes(values)
    independent_captures = len({item.capture_id for item in samples})
    all_zero = not any(raw)
    status = (
        "supported"
        if raw and independent_captures >= 2 and not all_zero
        else "candidate"
        if raw
        else "rejected"
    )
    return {
        "candidate_id": f"offset-{offset}-constant-run",
        "offset": offset,
        "width": len(raw),
        "status": status,
        "value_hex": raw.hex(),
        "sample_count": len(samples),
        "capture_count": independent_captures,
        "all_zero": all_zero,
        "supporting_examples": [
            _example(item, raw.hex(), raw.hex()) for item in samples
        ],
        "counterexamples": [],
    }


def _metadata_relation(
    samples: Sequence[CommonHeaderSample],
    relation: str,
    key: Callable[[CommonHeaderSample], Any],
) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    for offset in range(_FAMILY_SCAN_START, _COLUMN_LIMIT):
        present = [item for item in samples if len(item.derived_bytes) > offset]
        if len(present) != len(samples):
            continue
        grouped: dict[Any, list[CommonHeaderSample]] = defaultdict(list)
        for sample in present:
            grouped[key(sample)].append(sample)
        modes = {
            group: Counter(item.derived_bytes[offset] for item in items).most_common(1)[
                0
            ][0]
            for group, items in grouped.items()
        }
        if len(set(modes.values())) < 2:
            continue
        supporting: list[dict[str, Any]] = []
        counterexamples: list[dict[str, Any]] = []
        for group, items in grouped.items():
            expected = modes[group]
            for item in items:
                target_list = (
                    supporting
                    if item.derived_bytes[offset] == expected
                    else counterexamples
                )
                target_list.append(_example(item, item.derived_bytes[offset], expected))
        independent = all(
            len({item.capture_id for item in items}) >= 2 for items in grouped.values()
        )
        status = (
            "supported"
            if not counterexamples and independent
            else "candidate"
            if not counterexamples
            else "rejected"
        )
        fields.append(
            {
                "field_id": f"offset-{offset}-width-1",
                "offset": offset,
                "width": 1,
                "status": status,
                "values_by_metadata": [
                    {
                        "metadata_value": group,
                        "byte_value": value,
                        "hex": f"{value:02x}",
                    }
                    for group, value in sorted(
                        modes.items(), key=lambda item: repr(item[0])
                    )
                ],
                "supporting_examples": supporting,
                "counterexamples": counterexamples,
            }
        )
    supported_offsets = [
        item["offset"] for item in fields if item["status"] == "supported"
    ]
    run = _first_consecutive_run(supported_offsets)
    return {
        "relation": relation,
        "status": (
            "supported"
            if supported_offsets
            else "candidate"
            if fields and all(not item["counterexamples"] for item in fields)
            else "rejected"
        ),
        "first_supported_run": ({"offset": run[0], "width": len(run)} if run else None),
        "fields": fields,
    }


def _integer_relation_scan(
    samples: Sequence[CommonHeaderSample],
    relation: str,
    target: Callable[[CommonHeaderSample], int],
    *,
    scan_start: int,
) -> dict[str, Any]:
    fields = []
    for width in _INTEGER_WIDTHS:
        for offset in range(scan_start, _COLUMN_LIMIT - width + 1):
            for byte_order in _BYTE_ORDERS:
                candidate = _exact_integer_candidate(
                    samples,
                    candidate_id=f"offset-{offset}-width-{width}-{byte_order}",
                    offset=offset,
                    width=width,
                    byte_order=byte_order,
                    target=target,
                )
                if len(candidate["supporting_examples"]) >= 2:
                    fields.append(candidate)
    fields.sort(
        key=lambda item: (
            0 if item["status"] == "supported" else 1,
            len(item["counterexamples"]),
            -len(item["supporting_examples"]),
            item["offset"],
            item["width"],
            item["byte_order"],
        )
    )
    selected = fields[:8]
    return {
        "relation": relation,
        "status": (
            "supported"
            if any(item["status"] == "supported" for item in selected)
            else "candidate"
            if any(item["status"] == "candidate" for item in selected)
            else "rejected"
        ),
        "fields": selected,
    }


def _exact_integer_candidate(  # noqa: PLR0913
    samples: Sequence[CommonHeaderSample],
    *,
    candidate_id: str,
    offset: int,
    width: int,
    byte_order: ByteOrder,
    target: Callable[[CommonHeaderSample], int],
) -> dict[str, Any]:
    supporting: list[dict[str, Any]] = []
    counterexamples: list[dict[str, Any]] = []
    for sample in samples:
        expected = target(sample)
        if len(sample.derived_bytes) < offset + width:
            counterexamples.append(_example(sample, None, expected))
            continue
        observed = int.from_bytes(
            sample.derived_bytes[offset : offset + width], byte_order
        )
        target_list = supporting if observed == expected else counterexamples
        target_list.append(_example(sample, observed, expected))
    distinct_targets = {item["target_value"] for item in supporting}
    independent_captures = {item["capture_id"] for item in supporting}
    if counterexamples:
        status = "rejected"
    elif len(distinct_targets) >= 2 and len(independent_captures) >= 2:
        status = "supported"
    else:
        status = "candidate"
    return {
        "candidate_id": candidate_id,
        "offset": offset,
        "width": width,
        "byte_order": byte_order,
        "status": status,
        "supporting_examples": supporting,
        "counterexamples": counterexamples,
    }


def _first_structure_change(
    samples: Sequence[CommonHeaderSample],
    invariant: dict[str, Any],
    family: dict[str, Any],
) -> dict[str, Any]:
    first_variable = next(
        (
            offset
            for offset in range(9, _COLUMN_LIMIT)
            if len(
                {
                    item.derived_bytes[offset]
                    for item in samples
                    if len(item.derived_bytes) > offset
                }
            )
            > 1
        ),
        None,
    )
    family_field = next(
        (item for item in family["fields"] if item["offset"] == first_variable),
        None,
    )
    return {
        "shared_invariant_offset": invariant["offset"],
        "shared_invariant_width": invariant["width"],
        "first_variable_offset": first_variable,
        "first_variable_relation": family_field,
        "status": (
            "supported"
            if invariant["status"] == "supported"
            and family_field is not None
            and family_field["status"] == "supported"
            else "candidate"
        ),
        "parser_boundary_adoption": False,
    }


def _prefix_report(samples: Sequence[CommonHeaderSample]) -> dict[str, Any]:
    if not samples:
        return {"byte_length": 0, "hex": ""}
    prefix = samples[0].derived_bytes
    for sample in samples[1:]:
        prefix = prefix[: _common_prefix(prefix, sample.derived_bytes)]
    return {"byte_length": len(prefix), "hex": prefix.hex()}


def _on_mi_forms(samples: Sequence[CommonHeaderSample]) -> list[dict[str, Any]]:
    grouped: dict[tuple[int, str], list[CommonHeaderSample]] = defaultdict(list)
    for sample in samples:
        if sample.message_family == "onMI":
            grouped[(len(sample.derived_bytes), sample.derived_sha256)].append(sample)
    return [
        {
            "derived_length": length,
            "derived_sha256": digest,
            "occurrence_count": len(items),
            "capture_count": len({item.capture_id for item in items}),
            "associations": sorted({item.association for item in items}),
        }
        for (length, digest), items in sorted(grouped.items())
    ]


def _example(
    sample: CommonHeaderSample,
    observed_value: Any,
    target_value: Any,
) -> dict[str, Any]:
    return {
        "sample_id": _sample_id(sample),
        "capture_id": sample.capture_id,
        "timestamp": sample.timestamp,
        "message_family": sample.message_family,
        "association": sample.association,
        "infoSize": sample.info_size,
        "observed_value": observed_value,
        "target_value": target_value,
    }


def _distribution(values: Any) -> list[dict[str, Any]]:
    counts = Counter(values)
    return [
        {"value": value, "count": count}
        for value, count in sorted(counts.items(), key=lambda item: repr(item[0]))
    ]


def _first_consecutive_run(offsets: Sequence[int]) -> list[int]:
    if not offsets:
        return []
    run = [offsets[0]]
    for offset in offsets[1:]:
        if offset == run[-1] + 1:
            run.append(offset)
        else:
            break
    return run


def _association(roles: Sequence[str]) -> Association:
    if len(roles) != 1:
        return "unclassified"
    role = roles[0]
    if role == "request-associated":
        return "request-associated"
    if role == "cadence-associated":
        return "cadence-associated"
    return "unclassified"


def _sample_id(sample: CommonHeaderSample) -> str:
    return sha256(
        orjson.dumps(
            [
                sample.capture_id,
                sample.timestamp,
                sample.message_family,
                sample.association,
                sample.info_size,
                sample.derived_sha256,
            ]
        )
    ).hexdigest()[:20]


def _sample_sort_key(sample: CommonHeaderSample) -> tuple[str, str, str, str]:
    return sample.phase, sample.timestamp, sample.message_family, _sample_id(sample)


def _common_prefix(left: bytes, right: bytes) -> int:
    count = 0
    for left_byte, right_byte in zip(left, right, strict=False):
        if left_byte != right_byte:
            break
        count += 1
    return count


def _required_integer(record: VerifiedArtifactRecord, path: str) -> int:
    value = _verified_scalar(record, path)
    if isinstance(value, bool):
        raise CommonHeaderResearchError("Envelope value is not an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    raise CommonHeaderResearchError("Envelope value is not an integer")


def _verified_scalar(record: VerifiedArtifactRecord, path: str) -> Any:
    segment = _segment(record, path)
    if segment is not None:
        if segment.kind == "canonical-json-v1":
            try:
                return orjson.loads(segment.raw)
            except orjson.JSONDecodeError:
                return None
        if segment.kind == "json-string-utf8-value":
            try:
                return segment.raw.decode("utf-8")
            except UnicodeDecodeError:
                return None
    current: Any = record.sanitized_envelope
    for part in path.removeprefix("$.").split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _segment(
    record: VerifiedArtifactRecord,
    source_path: str,
) -> VerifiedOpaqueSegment | None:
    return next(
        (item for item in record.opaque_segments if item.source_path == source_path),
        None,
    )
