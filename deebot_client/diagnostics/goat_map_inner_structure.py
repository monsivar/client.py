"""Read-only structural research for opaque bytes beginning at offset 17."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
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
from .goat_map_on_ari_framing import collect_grouped_on_ari_observations
from .goat_map_representation import (
    RepresentationDecodeError,
    decode_strict_base64_representation,
)
from .goat_map_structural_header import (
    StructuralHeaderError,
    recognize_structural_header,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence
    from pathlib import Path

    from .goat_map_common_header import Association, MessageFamily

type ByteOrder = Literal["little", "big"]

_ANALYSIS_VERSION = "goat-static-inner-structure/v1"
_INFO_PATH = "$.body.data.info"
_SCAN_START = 17
_COLUMN_LIMIT = 64
_INTEGER_WIDTHS = (1, 2, 4)
_BYTE_ORDERS: tuple[ByteOrder, ...] = ("little", "big")
_MAX_INTEGER_FIELDS = 6


class InnerStructureResearchError(ValueError):
    """The immutable corpus cannot be analyzed safely or consistently."""


@dataclass(frozen=True, slots=True)
class InnerStructureSample:
    """One opaque derived value with only observable context metadata."""

    capture_id: str
    phase: str
    timestamp: str
    windows: tuple[str, ...]
    message_family: MessageFamily
    association: Association
    serial: int | None
    info_size: int
    event_transports: tuple[str, ...]
    control_transports: tuple[str, ...]
    derived_bytes: bytes
    derived_sha256: str


def analyze_inner_structure_corpus(
    artifact_dirs: Sequence[Path],
) -> dict[str, Any]:
    """Verify immutable artifacts and analyze bytes at offsets 17..63."""
    if not artifact_dirs:
        raise InnerStructureResearchError("At least one Phase 2 artifact is required")
    try:
        artifacts = sorted(
            (load_verified_phase2_artifact(path) for path in artifact_dirs),
            key=lambda item: (item.phase, item.capture_id),
        )
    except ArtifactDeltaError as err:
        raise InnerStructureResearchError(str(err)) from err
    capture_ids = [artifact.capture_id for artifact in artifacts]
    if len(capture_ids) != len(set(capture_ids)):
        raise InnerStructureResearchError("Corpus contains duplicate capture IDs")

    samples, exclusions = collect_inner_structure_samples(artifacts)
    report = analyze_inner_structure_samples(samples)
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


def collect_inner_structure_samples(
    artifacts: Sequence[VerifiedPhase2Artifact],
) -> tuple[list[InnerStructureSample], list[dict[str, Any]]]:
    """Collect proven onMI forms and complete grouped onArI streams."""
    samples: list[InnerStructureSample] = []
    exclusions: list[dict[str, Any]] = []
    for artifact in artifacts:
        markers = _control_markers(artifact.records)
        for record in artifact.records:
            if record.command != "onMI" or record.direction != "event":
                continue
            info = _segment(record, _INFO_PATH)
            if info is None or len(info.raw) not in {52, 876}:
                exclusions.append(
                    {
                        "capture_id": artifact.capture_id,
                        "sequence": record.sequence,
                        "message_family": "onMI",
                        "reason": "not-one-of-two-stable-representation-lengths",
                    }
                )
                continue
            try:
                derived = decode_strict_base64_representation(info.raw.decode("ascii"))
                info_size = _required_integer(record, "$.body.data.infoSize")
                recognize_structural_header(
                    derived,
                    envelope_info_size=info_size,
                )
            except (
                InnerStructureResearchError,
                RepresentationDecodeError,
                StructuralHeaderError,
                UnicodeDecodeError,
            ) as err:
                exclusions.append(
                    {
                        "capture_id": artifact.capture_id,
                        "sequence": record.sequence,
                        "message_family": "onMI",
                        "reason": type(err).__name__,
                    }
                )
                continue
            association: Association = (
                "request-associated" if len(info.raw) == 876 else "cadence-associated"
            )
            samples.append(
                InnerStructureSample(
                    capture_id=artifact.capture_id,
                    phase=artifact.phase,
                    timestamp=record.observed_at,
                    windows=(record.window,),
                    message_family="onMI",
                    association=association,
                    serial=None,
                    info_size=info_size,
                    event_transports=(record.transport,),
                    control_transports=(
                        markers.get(record.window, ())
                        if association == "request-associated"
                        else ()
                    ),
                    derived_bytes=derived,
                    derived_sha256=sha256(derived).hexdigest(),
                )
            )

    observations, grouped_exclusions = collect_grouped_on_ari_observations(artifacts)
    exclusions.extend(grouped_exclusions)
    for observation in observations:
        identity = observation.segment_set.identity
        try:
            info_size = _integer_value(identity.info_size)
            association = _association(observation.roles)
            derived = observation.segment_set.derived_concatenation
            recognize_structural_header(derived, envelope_info_size=info_size)
        except (InnerStructureResearchError, StructuralHeaderError) as err:
            exclusions.append(
                {
                    "capture_id": observation.capture_id,
                    "message_family": "onArI",
                    "reason": type(err).__name__,
                }
            )
            continue
        samples.append(
            InnerStructureSample(
                capture_id=observation.capture_id,
                phase=observation.phase,
                timestamp=observation.first_timestamp,
                windows=observation.windows,
                message_family="onArI",
                association=association,
                serial=identity.serial,
                info_size=info_size,
                event_transports=observation.event_transports,
                control_transports=observation.associated_control_transports,
                derived_bytes=derived,
                derived_sha256=observation.segment_set.derived_concatenation_sha256,
            )
        )
    return samples, exclusions


def analyze_inner_structure_samples(
    samples: Sequence[InnerStructureSample],
) -> dict[str, Any]:
    """Build deterministic metadata-only evidence for offsets 17..63."""
    if not samples:
        raise InnerStructureResearchError("At least one derived sample is required")
    ordered = sorted(samples, key=_sample_sort_key)
    for sample in ordered:
        if sha256(sample.derived_bytes).hexdigest() != sample.derived_sha256:
            message = f"Sample {_sample_id(sample)} has an inconsistent digest"
            raise InnerStructureResearchError(message)
        try:
            recognize_structural_header(
                sample.derived_bytes,
                envelope_info_size=sample.info_size,
            )
        except StructuralHeaderError as err:
            message = f"Sample {_sample_id(sample)} is outside the framing contract"
            raise InnerStructureResearchError(message) from err

    columns = [
        _column_report(ordered, offset) for offset in range(_SCAN_START, _COLUMN_LIMIT)
    ]
    family = _categorical_relation(
        ordered,
        relation="message-family",
        key=lambda item: item.message_family,
    )
    association = _categorical_relation(
        ordered,
        relation="association",
        key=lambda item: item.association,
    )
    family_association = _categorical_relation(
        ordered,
        relation="message-family-plus-association",
        key=lambda item: f"{item.message_family}:{item.association}",
    )
    on_ari = [item for item in ordered if item.message_family == "onArI"]
    serial = _categorical_relation(
        on_ari,
        relation="onArI-envelope-serial",
        key=lambda item: item.serial,
    )
    info_size = _integer_relation_scan(
        ordered,
        relation="equals-envelope-infoSize",
        target=lambda item: item.info_size,
    )
    total_length = _integer_relation_scan(
        ordered,
        relation="equals-derived-total-length",
        target=lambda item: len(item.derived_bytes),
    )
    relations = {
        "message_family": family,
        "association": association,
        "message_family_plus_association": family_association,
        "onArI_serial": serial,
        "infoSize": info_size,
        "derived_total_length": total_length,
    }
    next_structure = _next_structure_candidate(
        ordered,
        family_association,
        serial,
    )
    return {
        "schema_version": "goat-static-inner-structure-report/v1",
        "analysis_version": _ANALYSIS_VERSION,
        "analysis_kind": "opaque-read-only-offset-17-plus-structure-research",
        "artifact_modification": False,
        "structural_header_view_extended": False,
        "parser_implemented": False,
        "decoder_implemented": False,
        "opaque_full_values_in_report": False,
        "scan_range": {
            "start_offset_inclusive": _SCAN_START,
            "end_offset_exclusive": _COLUMN_LIMIT,
        },
        "corpus": {
            "sample_count": len(ordered),
            "capture_count": len({item.capture_id for item in ordered}),
            "message_family_distribution": _distribution(
                item.message_family for item in ordered
            ),
            "association_distribution": _distribution(
                item.association for item in ordered
            ),
            "control_transport_distribution": _distribution(
                _control_context(item) for item in ordered
            ),
        },
        "samples": [_sample_report(item) for item in ordered],
        "byte_column_inventory": columns,
        "offset_17_assessment": {
            "column": columns[0],
            "candidate_relations": {
                name: _field_at(relation, _SCAN_START)
                for name, relation in relations.items()
            },
            "api_extension_recommended": False,
        },
        "candidate_relations": relations,
        "next_evidence_based_structure": next_structure,
        "same_capture_same_role_length_variation": _same_context_variation(ordered),
        "legacy_ngiot_control_comparisons": _transport_control_comparisons(ordered),
        "interpretation_guard": (
            "Offsets and metadata correlations are structural observations only. "
            "Legacy/N-GIoT is retained as a control context, not an explanatory "
            "variable. No bytes at offset 17 or later are parsed or named by "
            "content semantics."
        ),
    }


def _column_report(
    samples: Sequence[InnerStructureSample],
    offset: int,
) -> dict[str, Any]:
    present = [item for item in samples if len(item.derived_bytes) > offset]
    return {
        "offset": offset,
        "sample_count": len(present),
        "capture_count": len({item.capture_id for item in present}),
        "missing_sample_count": len(samples) - len(present),
        "stability": _stability(present, offset, len(samples)),
        "values": _raw_values(present, offset),
        "by_message_family": _column_groups(
            present, offset, "message_family", lambda item: item.message_family
        ),
        "by_association": _column_groups(
            present, offset, "association", lambda item: item.association
        ),
        "by_family_association": _column_groups(
            present,
            offset,
            "family_association",
            lambda item: f"{item.message_family}:{item.association}",
        ),
        "by_serial": _column_groups(
            [item for item in present if item.serial is not None],
            offset,
            "serial",
            lambda item: item.serial,
        ),
        "by_infoSize": _column_groups(
            present, offset, "infoSize", lambda item: item.info_size
        ),
        "by_control_transport": _column_groups(
            present,
            offset,
            "control_transport",
            _control_context,
        ),
        "by_derived_total_length": _column_groups(
            present,
            offset,
            "derived_total_length",
            lambda item: len(item.derived_bytes),
        ),
    }


def _column_groups(
    samples: Sequence[InnerStructureSample],
    offset: int,
    key_name: str,
    key: Callable[[InnerStructureSample], Any],
) -> list[dict[str, Any]]:
    grouped: dict[Any, list[InnerStructureSample]] = defaultdict(list)
    for sample in samples:
        grouped[key(sample)].append(sample)
    return [
        {
            key_name: group,
            "sample_count": len(items),
            "capture_count": len({item.capture_id for item in items}),
            "stability": _stability(items, offset, len(items)),
            "values": _raw_values(items, offset),
        }
        for group, items in sorted(grouped.items(), key=lambda item: repr(item[0]))
    ]


def _raw_values(
    samples: Sequence[InnerStructureSample],
    offset: int,
) -> list[dict[str, Any]]:
    grouped: dict[int, list[InnerStructureSample]] = defaultdict(list)
    for sample in samples:
        grouped[sample.derived_bytes[offset]].append(sample)
    return [
        {
            "value": value,
            "hex": f"{value:02x}",
            "sample_count": len(items),
            "capture_count": len({item.capture_id for item in items}),
            "contexts": _value_contexts(items),
            "sample_ids": sorted(_sample_id(item) for item in items),
        }
        for value, items in sorted(grouped.items())
    ]


def _value_contexts(samples: Sequence[InnerStructureSample]) -> list[dict[str, Any]]:
    counts = Counter(
        (
            item.message_family,
            item.association,
            item.serial,
            _control_context(item),
        )
        for item in samples
    )
    return [
        {
            "message_family": family,
            "association": association,
            "serial": serial,
            "control_transport": transport,
            "sample_count": count,
        }
        for (family, association, serial, transport), count in sorted(
            counts.items(), key=lambda item: repr(item[0])
        )
    ]


def _stability(
    samples: Sequence[InnerStructureSample],
    offset: int,
    expected_count: int,
) -> str:
    if not samples:
        return "not-observed"
    values = {item.derived_bytes[offset] for item in samples}
    if len(values) == 1 and len(samples) == expected_count:
        return "constant"
    if len(values) == 1:
        return "constant-among-present"
    return "variable"


def _categorical_relation(
    samples: Sequence[InnerStructureSample],
    *,
    relation: str,
    key: Callable[[InnerStructureSample], Any],
) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    for offset in range(_SCAN_START, _COLUMN_LIMIT):
        present = [item for item in samples if len(item.derived_bytes) > offset]
        if not present:
            continue
        grouped: dict[Any, list[InnerStructureSample]] = defaultdict(list)
        for sample in present:
            grouped[key(sample)].append(sample)
        if len(grouped) < 2:
            continue
        modes = {
            group: Counter(item.derived_bytes[offset] for item in items).most_common(1)[
                0
            ][0]
            for group, items in grouped.items()
        }
        group_value_sets = {
            group: {item.derived_bytes[offset] for item in items}
            for group, items in grouped.items()
        }
        if len(set(modes.values())) < 2 and all(
            len(values) == 1 for values in group_value_sets.values()
        ):
            continue
        supporting: list[dict[str, Any]] = []
        counterexamples: list[dict[str, Any]] = []
        for group, items in grouped.items():
            expected = modes[group]
            for item in items:
                example = _example(item, item.derived_bytes[offset], expected)
                (
                    supporting
                    if item.derived_bytes[offset] == expected
                    else counterexamples
                ).append(example)
        missing = [item for item in samples if len(item.derived_bytes) <= offset]
        counterexamples.extend(
            _example(item, None, modes.get(key(item))) for item in missing
        )
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
                "values_by_context": [
                    {
                        "context": group,
                        "value": value,
                        "hex": f"{value:02x}",
                        "sample_count": len(grouped[group]),
                        "capture_count": len(
                            {item.capture_id for item in grouped[group]}
                        ),
                    }
                    for group, value in sorted(
                        modes.items(), key=lambda item: repr(item[0])
                    )
                ],
                "supporting_examples": supporting,
                "counterexamples": counterexamples,
            }
        )
    return {
        "relation": relation,
        "status": _relation_status(fields),
        "supported_runs": _supported_runs(fields),
        "fields": fields,
    }


def _integer_relation_scan(
    samples: Sequence[InnerStructureSample],
    *,
    relation: str,
    target: Callable[[InnerStructureSample], int],
) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    tested = 0
    for width in _INTEGER_WIDTHS:
        byte_orders: tuple[ByteOrder, ...] = ("little",) if width == 1 else _BYTE_ORDERS
        for offset in range(_SCAN_START, _COLUMN_LIMIT - width + 1):
            for byte_order in byte_orders:
                tested += 1
                supporting: list[dict[str, Any]] = []
                counterexamples: list[dict[str, Any]] = []
                for sample in samples:
                    expected = target(sample)
                    observed = (
                        int.from_bytes(
                            sample.derived_bytes[offset : offset + width],
                            byte_order,
                        )
                        if len(sample.derived_bytes) >= offset + width
                        else None
                    )
                    (supporting if observed == expected else counterexamples).append(
                        _example(sample, observed, expected)
                    )
                targets = {item["target_value"] for item in supporting}
                captures = {item["capture_id"] for item in supporting}
                status = (
                    "supported"
                    if not counterexamples and len(targets) >= 2 and len(captures) >= 2
                    else "candidate"
                    if not counterexamples
                    else "rejected"
                )
                fields.append(
                    {
                        "field_id": f"offset-{offset}-width-{width}-{byte_order}",
                        "offset": offset,
                        "width": width,
                        "byte_order": byte_order,
                        "status": status,
                        "supporting_examples": supporting,
                        "counterexamples": counterexamples,
                    }
                )
    fields.sort(
        key=lambda item: (
            0 if item["status"] == "supported" else 1,
            0 if item["status"] == "candidate" else 1,
            -len(item["supporting_examples"]),
            len(item["counterexamples"]),
            item["offset"],
            item["width"],
            item["byte_order"],
        )
    )
    selected = fields[:_MAX_INTEGER_FIELDS]
    return {
        "relation": relation,
        "status": _relation_status(selected),
        "tested_candidate_count": tested,
        "reported_candidate_limit": _MAX_INTEGER_FIELDS,
        "supported_runs": [],
        "fields": selected,
    }


def _relation_status(fields: Sequence[dict[str, Any]]) -> str:
    if any(item["status"] == "supported" for item in fields):
        return "supported"
    if any(item["status"] == "candidate" for item in fields):
        return "candidate"
    return "rejected"


def _field_at(relation: dict[str, Any], offset: int) -> dict[str, Any] | None:
    return next(
        (item for item in relation["fields"] if item["offset"] == offset),
        None,
    )


def _supported_runs(fields: Sequence[dict[str, Any]]) -> list[dict[str, int]]:
    offsets = sorted(item["offset"] for item in fields if item["status"] == "supported")
    if not offsets:
        return []
    runs: list[list[int]] = [[offsets[0]]]
    for offset in offsets[1:]:
        if offset == runs[-1][-1] + 1:
            runs[-1].append(offset)
        else:
            runs.append([offset])
    return [{"offset": run[0], "width": len(run)} for run in runs]


def _next_structure_candidate(
    samples: Sequence[InnerStructureSample],
    family_association: dict[str, Any],
    serial: dict[str, Any],
) -> dict[str, Any]:
    joint_run = next(
        (
            item
            for item in family_association["supported_runs"]
            if item["offset"] == _SCAN_START
        ),
        None,
    )
    serial_run = next(
        (item for item in serial["supported_runs"] if item["offset"] == _SCAN_START),
        None,
    )
    if joint_run is None:
        return {
            "status": "rejected",
            "reason": "no-supported-context-stable-run-starting-at-offset-17",
            "structural_header_api_extension_recommended": False,
        }
    width = joint_run["width"]
    joint_candidate = _run_candidate(
        samples,
        relation="message-family-plus-association",
        key=lambda item: f"{item.message_family}:{item.association}",
        offset=_SCAN_START,
        width=width,
    )
    on_ari = [item for item in samples if item.message_family == "onArI"]
    serial_candidate = (
        _run_candidate(
            on_ari,
            relation="onArI-envelope-serial",
            key=lambda item: item.serial,
            offset=_SCAN_START,
            width=min(width, serial_run["width"]),
        )
        if serial_run is not None
        else None
    )
    return {
        "status": joint_candidate["status"],
        "offset": _SCAN_START,
        "width": width,
        "end_offset_inclusive": _SCAN_START + width - 1,
        "first_following_offset": _SCAN_START + width,
        "classification": "context-stable-byte-run-candidate",
        "message_family_plus_association": joint_candidate,
        "onArI_serial": serial_candidate,
        "internal_field_boundaries": None,
        "structural_header_api_extension_recommended": False,
    }


def _run_candidate(
    samples: Sequence[InnerStructureSample],
    *,
    relation: str,
    key: Callable[[InnerStructureSample], Any],
    offset: int,
    width: int,
) -> dict[str, Any]:
    grouped: dict[Any, list[InnerStructureSample]] = defaultdict(list)
    for sample in samples:
        grouped[key(sample)].append(sample)
    modes: dict[Any, bytes] = {}
    for group, items in grouped.items():
        candidates = Counter(
            item.derived_bytes[offset : offset + width]
            for item in items
            if len(item.derived_bytes) >= offset + width
        )
        if candidates:
            modes[group] = candidates.most_common(1)[0][0]
    supporting: list[dict[str, Any]] = []
    counterexamples: list[dict[str, Any]] = []
    for group, items in grouped.items():
        expected = modes.get(group)
        for item in items:
            observed = (
                item.derived_bytes[offset : offset + width]
                if len(item.derived_bytes) >= offset + width
                else None
            )
            example = _example(
                item,
                observed.hex() if observed is not None else None,
                expected.hex() if expected is not None else None,
            )
            (supporting if observed == expected else counterexamples).append(example)
    independent = all(
        len({item.capture_id for item in items}) >= 2 for items in grouped.values()
    )
    status = (
        "supported"
        if not counterexamples and independent and len(set(modes.values())) >= 2
        else "candidate"
        if not counterexamples
        else "rejected"
    )
    return {
        "relation": relation,
        "status": status,
        "offset": offset,
        "width": width,
        "values_by_context": [
            {
                "context": group,
                "raw_hex": value.hex(),
                "sample_count": len(grouped[group]),
                "capture_count": len({item.capture_id for item in grouped[group]}),
            }
            for group, value in sorted(modes.items(), key=lambda item: repr(item[0]))
        ],
        "supporting_examples": supporting,
        "counterexamples": counterexamples,
    }


def _same_context_variation(
    samples: Sequence[InnerStructureSample],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[InnerStructureSample]] = defaultdict(list)
    for sample in samples:
        grouped[(sample.capture_id, sample.message_family, sample.association)].append(
            sample
        )
    reports: list[dict[str, Any]] = []
    for (capture_id, family, association), items in sorted(grouped.items()):
        variants: dict[tuple[int, str], list[InnerStructureSample]] = defaultdict(list)
        for item in items:
            variants[(len(item.derived_bytes), item.derived_sha256)].append(item)
        lengths = {length for length, _ in variants}
        if len(lengths) < 2:
            continue
        ordered_variants = sorted(variants.items())
        reports.append(
            {
                "capture_id": capture_id,
                "message_family": family,
                "association": association,
                "distinct_length_count": len(lengths),
                "variants": [
                    {
                        "derived_total_length": length,
                        "derived_sha256": digest,
                        "occurrence_count": len(variant_samples),
                        "control_transports": sorted(
                            {_control_context(item) for item in variant_samples}
                        ),
                    }
                    for (length, digest), variant_samples in ordered_variants
                ],
                "pairwise_structure": [
                    _pair_structure(left[1][0], right[1][0])
                    for left, right in combinations(ordered_variants, 2)
                ],
            }
        )
    return reports


def _transport_control_comparisons(
    samples: Sequence[InnerStructureSample],
) -> dict[str, Any]:
    grouped: dict[tuple[str, str, str], list[InnerStructureSample]] = defaultdict(list)
    for sample in samples:
        grouped[(sample.capture_id, sample.message_family, sample.association)].append(
            sample
        )
    comparisons: list[dict[str, Any]] = []
    for (capture_id, family, association), items in sorted(grouped.items()):
        legacy = [item for item in items if _control_context(item) == "legacy"]
        ngiot = [item for item in items if _control_context(item) == "ngiot"]
        for left, right in zip(legacy, ngiot, strict=False):
            comparisons.append(
                {
                    "capture_id": capture_id,
                    "message_family": family,
                    "association": association,
                    **_pair_structure(left, right),
                }
            )
    identical_count = sum(
        1 for item in comparisons if item["identical_derived_bytes"] is True
    )
    return {
        "comparison_count": len(comparisons),
        "identical_derived_count": identical_count,
        "different_derived_count": len(comparisons) - identical_count,
        "comparisons": comparisons,
        "interpretation": "control-only-no-causal-attribution",
    }


def _pair_structure(
    left: InnerStructureSample,
    right: InnerStructureSample,
) -> dict[str, Any]:
    first_difference = _first_difference(left.derived_bytes, right.derived_bytes)
    inner_first_difference = _first_difference_from(
        left.derived_bytes,
        right.derived_bytes,
        _SCAN_START,
    )
    return {
        "left_sample_id": _sample_id(left),
        "right_sample_id": _sample_id(right),
        "left_length": len(left.derived_bytes),
        "right_length": len(right.derived_bytes),
        "identical_derived_bytes": left.derived_bytes == right.derived_bytes,
        "first_differing_offset": first_difference,
        "first_differing_offset_at_or_after_17": inner_first_difference,
        "common_prefix_from_offset_17": _common_prefix_from(
            left.derived_bytes,
            right.derived_bytes,
            _SCAN_START,
        ),
    }


def _sample_report(item: InnerStructureSample) -> dict[str, Any]:
    return {
        "sample_id": _sample_id(item),
        "capture_id": item.capture_id,
        "phase": item.phase,
        "timestamp": item.timestamp,
        "windows": list(item.windows),
        "message_family": item.message_family,
        "association": item.association,
        "serial": item.serial,
        "infoSize": item.info_size,
        "event_transports": list(item.event_transports),
        "control_transports": list(item.control_transports),
        "control_transport_context": _control_context(item),
        "derived_total_length": len(item.derived_bytes),
        "derived_sha256": item.derived_sha256,
    }


def _example(
    item: InnerStructureSample,
    observed_value: Any,
    target_value: Any,
) -> dict[str, Any]:
    return {
        "sample_id": _sample_id(item),
        "capture_id": item.capture_id,
        "timestamp": item.timestamp,
        "message_family": item.message_family,
        "association": item.association,
        "serial": item.serial,
        "infoSize": item.info_size,
        "derived_total_length": len(item.derived_bytes),
        "control_transport": _control_context(item),
        "observed_value": observed_value,
        "target_value": target_value,
    }


def _control_context(item: InnerStructureSample) -> str:
    if item.control_transports:
        return ",".join(sorted(item.control_transports))
    if item.association == "request-associated":
        return "unattributed"
    return "none"


def _control_markers(
    records: Sequence[VerifiedArtifactRecord],
) -> dict[str, tuple[str, ...]]:
    markers: dict[str, set[str]] = defaultdict(set)
    for record in records:
        if (
            record.command == "getMI"
            and record.direction == "response"
            and record.transport in {"legacy", "ngiot"}
        ):
            markers[record.window].add(record.transport)
    return {window: tuple(sorted(values)) for window, values in markers.items()}


def _association(roles: Sequence[str]) -> Association:
    if len(roles) != 1:
        return "unclassified"
    if roles[0] == "request-associated":
        return "request-associated"
    if roles[0] == "cadence-associated":
        return "cadence-associated"
    return "unclassified"


def _required_integer(record: VerifiedArtifactRecord, path: str) -> int:
    value = _verified_scalar(record, path)
    return _integer_value(value)


def _integer_value(value: Any) -> int:
    if isinstance(value, bool):
        raise InnerStructureResearchError("Envelope value is not an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    raise InnerStructureResearchError("Envelope value is not an integer")


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


def _sample_id(item: InnerStructureSample) -> str:
    return sha256(
        orjson.dumps(
            [
                item.capture_id,
                item.timestamp,
                item.message_family,
                item.association,
                item.serial,
                item.info_size,
                item.derived_sha256,
            ]
        )
    ).hexdigest()[:20]


def _sample_sort_key(item: InnerStructureSample) -> tuple[str, str, str, str]:
    return item.phase, item.timestamp, item.message_family, _sample_id(item)


def _first_difference(left: bytes, right: bytes) -> int | None:
    for offset, (left_byte, right_byte) in enumerate(zip(left, right, strict=False)):
        if left_byte != right_byte:
            return offset
    if len(left) != len(right):
        return min(len(left), len(right))
    return None


def _common_prefix_from(left: bytes, right: bytes, offset: int) -> int:
    count = 0
    for left_byte, right_byte in zip(left[offset:], right[offset:], strict=False):
        if left_byte != right_byte:
            break
        count += 1
    return count


def _first_difference_from(left: bytes, right: bytes, offset: int) -> int | None:
    relative = _first_difference(left[offset:], right[offset:])
    return offset + relative if relative is not None else None


def _distribution(values: Iterable[Any]) -> list[dict[str, Any]]:
    counts = Counter(values)
    return [
        {"value": value, "count": count}
        for value, count in sorted(counts.items(), key=lambda item: repr(item[0]))
    ]
