"""Read-only structural research within exact offset-17..33 signatures."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
from itertools import combinations, zip_longest
from typing import TYPE_CHECKING, Any, Literal

from .goat_map_delta import ArtifactDeltaError, load_verified_phase2_artifact
from .goat_map_inner_structure import (
    InnerStructureSample,
    collect_inner_structure_samples,
)
from .goat_map_inner_structure_view import (
    InnerStructureViewError,
    ObservedContextClass,
    recognize_inner_structure,
)
from .goat_map_structural_header import (
    StructuralHeaderError,
    recognize_structural_header,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence
    from pathlib import Path

type ByteOrder = Literal["little", "big"]

_ANALYSIS_VERSION = "goat-static-body-structure/v2"
_ABSOLUTE_BODY_OFFSET = 34
_COLUMN_LIMIT = 64
_INTEGER_WIDTHS = (1, 2, 4)
_BYTE_ORDERS: tuple[ByteOrder, ...] = ("little", "big")
_MAX_INTEGER_FIELDS = 6
_REPETITION_WIDTHS = (2, 4, 8, 16)
_MAX_REPETITION_CANDIDATES = 12
_PREVIEW_LIMIT = 32


class BodyStructureResearchError(ValueError):
    """The immutable body corpus cannot be analyzed safely or consistently."""


@dataclass(frozen=True, slots=True)
class BodyStructureSample:
    """One exact context signature and its opaque offset-34+ remainder."""

    source: InnerStructureSample
    context_signature_raw: bytes
    observed_context_class: ObservedContextClass
    remainder: bytes
    remainder_sha256: str


def analyze_body_structure_corpus(
    artifact_dirs: Sequence[Path],
) -> dict[str, Any]:
    """Verify artifacts and analyze each exact context signature separately."""
    if not artifact_dirs:
        raise BodyStructureResearchError("At least one Phase 2 artifact is required")
    try:
        artifacts = sorted(
            (load_verified_phase2_artifact(path) for path in artifact_dirs),
            key=lambda item: (item.phase, item.capture_id),
        )
    except ArtifactDeltaError as err:
        raise BodyStructureResearchError(str(err)) from err
    capture_ids = [artifact.capture_id for artifact in artifacts]
    if len(capture_ids) != len(set(capture_ids)):
        raise BodyStructureResearchError("Corpus contains duplicate capture IDs")

    inner_samples, exclusions = collect_inner_structure_samples(artifacts)
    body_samples, body_exclusions = collect_body_structure_samples(inner_samples)
    exclusions.extend(body_exclusions)
    report = analyze_body_structure_samples(body_samples)
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


def collect_body_structure_samples(
    samples: Sequence[InnerStructureSample],
) -> tuple[list[BodyStructureSample], list[dict[str, Any]]]:
    """Apply existing views and preserve each exact signature/remainder pair."""
    collected: list[BodyStructureSample] = []
    exclusions: list[dict[str, Any]] = []
    for sample in samples:
        try:
            header = recognize_structural_header(
                sample.derived_bytes,
                envelope_info_size=sample.info_size,
            )
            inner = recognize_inner_structure(
                header,
                envelope_serial=sample.serial,
            )
        except (StructuralHeaderError, InnerStructureViewError) as err:
            exclusions.append(
                {
                    "capture_id": sample.capture_id,
                    "sample_id": _inner_sample_id(sample),
                    "reason": type(err).__name__,
                }
            )
            continue
        collected.append(
            BodyStructureSample(
                source=sample,
                context_signature_raw=inner.context_signature_raw,
                observed_context_class=inner.observed_context_class,
                remainder=inner.remainder,
                remainder_sha256=sha256(inner.remainder).hexdigest(),
            )
        )
    return collected, exclusions


def analyze_body_structure_samples(
    samples: Sequence[BodyStructureSample],
) -> dict[str, Any]:
    """Build deterministic metadata-only evidence per exact signature."""
    if not samples:
        raise BodyStructureResearchError("At least one body sample is required")
    ordered = sorted(samples, key=_sample_sort_key)
    for sample in ordered:
        if sha256(sample.remainder).hexdigest() != sample.remainder_sha256:
            message = f"Sample {_sample_id(sample)} has an inconsistent body digest"
            raise BodyStructureResearchError(message)
    grouped: dict[bytes, list[BodyStructureSample]] = defaultdict(list)
    for sample in ordered:
        grouped[sample.context_signature_raw].append(sample)
    group_reports = [
        _group_report(signature, items) for signature, items in grouped.items()
    ]
    group_reports.sort(key=_group_priority_sort_key)
    for priority, group in enumerate(group_reports, start=1):
        group["analysis_priority"] = priority
    return {
        "schema_version": "goat-static-body-structure-report/v2",
        "analysis_version": _ANALYSIS_VERSION,
        "analysis_kind": "opaque-read-only-exact-signature-body-research",
        "artifact_modification": False,
        "body_parser_implemented": False,
        "decoder_implemented": False,
        "opaque_full_values_in_report": False,
        "grouping_key": "exact-context-signature-raw-bytes",
        "absolute_body_offset": _ABSOLUTE_BODY_OFFSET,
        "corpus": {
            "sample_count": len(ordered),
            "capture_count": len({item.source.capture_id for item in ordered}),
            "exact_signature_count": len(grouped),
            "observed_context_class_distribution": _distribution(
                item.observed_context_class for item in ordered
            ),
        },
        "priority_order": [
            {
                "priority": group["analysis_priority"],
                "signature_id": group["signature_identity"]["signature_id"],
                "context_signature_hex": group["signature_identity"][
                    "context_signature_hex"
                ],
                "observed_context_classes": group["signature_identity"][
                    "observed_context_classes"
                ],
                "reason": group["priority_evidence"]["reason"],
                "max_identical_cross_capture_sample_count": group["priority_evidence"][
                    "max_identical_cross_capture_sample_count"
                ],
                "max_identical_cross_capture_capture_count": group["priority_evidence"][
                    "max_identical_cross_capture_capture_count"
                ],
                "max_cross_capture_shared_edge_bytes": group["priority_evidence"][
                    "max_cross_capture_shared_edge_bytes"
                ],
            }
            for group in group_reports
        ],
        "signature_groups": group_reports,
        "interpretation_guard": (
            "Every group is keyed by byte-identical offsets 17..33. Different "
            "signatures are never merged, including signatures sharing one "
            "observed context class. Lengths, integer candidates, repetitions, "
            "and byte comparisons are structural observations only."
        ),
    }


def _group_report(
    signature: bytes,
    samples: Sequence[BodyStructureSample],
) -> dict[str, Any]:
    ordered = sorted(samples, key=_sample_sort_key)
    pairs = [_pair_report(left, right) for left, right in combinations(ordered, 2)]
    variants = _digest_variants(ordered)
    prefix = _common_prefix_all([item.remainder for item in ordered])
    suffix = _common_suffix_all([item.remainder for item in ordered])
    first_difference = _first_group_difference(ordered)
    structural_candidates = _structural_candidates(
        ordered,
        variants=variants,
        common_prefix=prefix,
        common_suffix=suffix,
        first_difference=first_difference,
    )
    relations = {
        "infoSize": _integer_relation_scan(
            ordered,
            relation="equals-envelope-infoSize",
            target=lambda item: item.source.info_size,
        ),
        "derived_total_length": _integer_relation_scan(
            ordered,
            relation="equals-derived-total-length",
            target=lambda item: len(item.source.derived_bytes),
        ),
        "remainder_length": _integer_relation_scan(
            ordered,
            relation="equals-remainder-length",
            target=lambda item: len(item.remainder),
        ),
        "onArI_serial": _serial_relation(ordered),
        "assembled_index": {
            "status": "rejected",
            "reason": "no-single-index-metadata-exists-after-complete-segment-grouping",
            "fields": [],
            "supporting_examples": [],
            "counterexamples": [],
        },
    }
    return {
        "signature_identity": {
            "signature_id": sha256(signature).hexdigest()[:20],
            "context_signature_hex": signature.hex(),
            "context_signature_sha256": sha256(signature).hexdigest(),
            "observed_context_classes": sorted(
                {item.observed_context_class for item in ordered}
            ),
            "message_families": sorted(
                {item.source.message_family for item in ordered}
            ),
            "serial_values": sorted(
                {
                    item.source.serial
                    for item in ordered
                    if item.source.serial is not None
                }
            ),
        },
        "sample_count": len(ordered),
        "capture_count": len({item.source.capture_id for item in ordered}),
        "samples": [_sample_report(item) for item in ordered],
        "remainder_variants": variants,
        "common_structure": {
            "common_prefix_length": len(prefix),
            "common_prefix_sha256": sha256(prefix).hexdigest() if prefix else None,
            "common_prefix_preview_hex": prefix[:_PREVIEW_LIMIT].hex(),
            "common_prefix_preview_truncated": len(prefix) > _PREVIEW_LIMIT,
            "common_suffix_length": len(suffix),
            "common_suffix_sha256": sha256(suffix).hexdigest() if suffix else None,
            "common_suffix_preview_hex": suffix[-_PREVIEW_LIMIT:].hex(),
            "common_suffix_preview_truncated": len(suffix) > _PREVIEW_LIMIT,
            "first_differing_remainder_offset": first_difference,
            "first_differing_absolute_offset": (
                _ABSOLUTE_BODY_OFFSET + first_difference
                if first_difference is not None
                else None
            ),
        },
        "byte_column_inventory": [
            _column_report(ordered, offset) for offset in range(_COLUMN_LIMIT)
        ],
        "structural_candidates": structural_candidates,
        "candidate_relations": relations,
        "repeating_structure_candidates": _repetition_candidates(ordered),
        "same_capture_repeatability": _repeatability_report(
            [item for item in pairs if item["same_capture"] is True]
        ),
        "cross_capture_repeatability": _repeatability_report(
            [item for item in pairs if item["same_capture"] is False]
        ),
        "priority_evidence": _priority_evidence(ordered, variants, pairs),
        "body_parser_recommended": False,
    }


def _structural_candidates(
    samples: Sequence[BodyStructureSample],
    *,
    variants: Sequence[dict[str, Any]],
    common_prefix: bytes,
    common_suffix: bytes,
    first_difference: int | None,
) -> dict[str, Any]:
    capture_count = len({item.source.capture_id for item in samples})
    largest_variant = max(
        variants,
        key=lambda item: (
            item["capture_count"],
            item["sample_count"],
            item["remainder_length"],
            item["remainder_sha256"],
        ),
    )
    other_variants = [
        item
        for item in variants
        if item["remainder_sha256"] != largest_variant["remainder_sha256"]
        or item["remainder_length"] != largest_variant["remainder_length"]
    ]
    exact_status = (
        "supported"
        if len(variants) == 1 and capture_count >= 2
        else "candidate"
        if largest_variant["capture_count"] >= 2
        else "rejected"
    )
    has_observed_boundary = (
        first_difference is not None and bool(common_prefix) and capture_count >= 2
    )
    prefix_status = (
        "supported"
        if has_observed_boundary
        else "candidate"
        if first_difference is not None and bool(common_prefix)
        else "rejected"
    )
    suffix_status = (
        "supported"
        if first_difference is not None and bool(common_suffix) and capture_count >= 2
        else "candidate"
        if first_difference is not None and bool(common_suffix)
        else "rejected"
    )
    stable_example = {
        "remainder_length": largest_variant["remainder_length"],
        "remainder_sha256": largest_variant["remainder_sha256"],
        "sample_count": largest_variant["sample_count"],
        "capture_count": largest_variant["capture_count"],
        "sample_ids": largest_variant["sample_ids"],
    }
    return {
        "exact_remainder_repeatability": {
            "status": exact_status,
            "relation": "byte-identical-offset-34-plus-remainder",
            "supporting_examples": [stable_example],
            "counterexamples": other_variants,
        },
        "stable_common_prefix_boundary": {
            "status": prefix_status,
            "relation": "all-samples-share-prefix-before-first-observed-variation",
            "common_prefix_length": len(common_prefix),
            "first_differing_remainder_offset": first_difference,
            "first_differing_absolute_offset": (
                _ABSOLUTE_BODY_OFFSET + first_difference
                if first_difference is not None
                else None
            ),
            "supporting_examples": (
                [_sample_reference(item) for item in samples]
                if prefix_status != "rejected"
                else []
            ),
            "counterexamples": [],
            "rejection_reason": (
                "no-observed-variation-after-a-shared-prefix"
                if prefix_status == "rejected"
                else None
            ),
        },
        "stable_common_suffix": {
            "status": suffix_status,
            "relation": "all-samples-share-suffix-after-observed-variation",
            "common_suffix_length": len(common_suffix),
            "supporting_examples": (
                [_sample_reference(item) for item in samples]
                if suffix_status != "rejected"
                else []
            ),
            "counterexamples": [],
            "rejection_reason": (
                "no-shared-suffix-after-observed-variation"
                if suffix_status == "rejected"
                else None
            ),
        },
    }


def _sample_reference(item: BodyStructureSample) -> dict[str, Any]:
    return {
        "sample_id": _sample_id(item),
        "capture_id": item.source.capture_id,
        "timestamp": item.source.timestamp,
        "remainder_length": len(item.remainder),
        "remainder_sha256": item.remainder_sha256,
    }


def _digest_variants(samples: Sequence[BodyStructureSample]) -> list[dict[str, Any]]:
    grouped: dict[tuple[int, str], list[BodyStructureSample]] = defaultdict(list)
    for sample in samples:
        grouped[(len(sample.remainder), sample.remainder_sha256)].append(sample)
    return [
        {
            "remainder_length": length,
            "remainder_sha256": digest,
            "sample_count": len(items),
            "capture_count": len({item.source.capture_id for item in items}),
            "sample_ids": sorted(_sample_id(item) for item in items),
        }
        for (length, digest), items in sorted(grouped.items())
    ]


def _column_report(
    samples: Sequence[BodyStructureSample],
    remainder_offset: int,
) -> dict[str, Any]:
    present = [item for item in samples if len(item.remainder) > remainder_offset]
    grouped: dict[int, list[BodyStructureSample]] = defaultdict(list)
    for sample in present:
        grouped[sample.remainder[remainder_offset]].append(sample)
    return {
        "remainder_offset": remainder_offset,
        "absolute_offset": _ABSOLUTE_BODY_OFFSET + remainder_offset,
        "sample_count": len(present),
        "capture_count": len({item.source.capture_id for item in present}),
        "missing_sample_count": len(samples) - len(present),
        "stability": (
            "not-observed"
            if not present
            else "constant"
            if len(grouped) == 1 and len(present) == len(samples)
            else "constant-among-present"
            if len(grouped) == 1
            else "variable"
        ),
        "values": [
            {
                "value": value,
                "hex": f"{value:02x}",
                "sample_count": len(items),
                "capture_count": len({item.source.capture_id for item in items}),
                "sample_ids": sorted(_sample_id(item) for item in items),
            }
            for value, items in sorted(grouped.items())
        ],
    }


def _integer_relation_scan(
    samples: Sequence[BodyStructureSample],
    *,
    relation: str,
    target: Callable[[BodyStructureSample], int],
) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    tested = 0
    for width in _INTEGER_WIDTHS:
        byte_orders: tuple[ByteOrder, ...] = ("little",) if width == 1 else _BYTE_ORDERS
        for offset in range(_COLUMN_LIMIT - width + 1):
            for byte_order in byte_orders:
                tested += 1
                supporting: list[dict[str, Any]] = []
                counterexamples: list[dict[str, Any]] = []
                for sample in samples:
                    expected = target(sample)
                    observed = (
                        int.from_bytes(
                            sample.remainder[offset : offset + width],
                            byte_order,
                        )
                        if len(sample.remainder) >= offset + width
                        else None
                    )
                    example = _example(sample, observed, expected)
                    (supporting if observed == expected else counterexamples).append(
                        example
                    )
                distinct_targets = {item["target_value"] for item in supporting}
                captures = {item["capture_id"] for item in supporting}
                status = (
                    "supported"
                    if not counterexamples
                    and len(distinct_targets) >= 2
                    and len(captures) >= 2
                    else "candidate"
                    if not counterexamples
                    else "rejected"
                )
                fields.append(
                    {
                        "field_id": f"remainder-{offset}-width-{width}-{byte_order}",
                        "remainder_offset": offset,
                        "absolute_offset": _ABSOLUTE_BODY_OFFSET + offset,
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
            item["remainder_offset"],
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
        "fields": selected,
    }


def _serial_relation(samples: Sequence[BodyStructureSample]) -> dict[str, Any]:
    on_ari = [item for item in samples if item.source.serial is not None]
    if not on_ari:
        return {
            "relation": "equals-envelope-serial",
            "status": "rejected",
            "reason": "signature-group-has-no-envelope-serial-metadata",
            "fields": [],
        }
    return _integer_relation_scan(
        on_ari,
        relation="equals-envelope-serial",
        target=lambda item: item.source.serial or 0,
    )


def _relation_status(fields: Sequence[dict[str, Any]]) -> str:
    if any(item["status"] == "supported" for item in fields):
        return "supported"
    if any(item["status"] == "candidate" for item in fields):
        return "candidate"
    return "rejected"


def _repetition_candidates(
    samples: Sequence[BodyStructureSample],
) -> dict[str, Any]:
    occurrences: dict[tuple[int, int, int, str], list[BodyStructureSample]] = (
        defaultdict(list)
    )
    for sample in samples:
        for width in _REPETITION_WIDTHS:
            offset = 0
            while offset + width * 3 <= len(sample.remainder):
                block = sample.remainder[offset : offset + width]
                repeat_count = 1
                while (
                    offset + (repeat_count + 1) * width <= len(sample.remainder)
                    and sample.remainder[
                        offset + repeat_count * width : offset
                        + (repeat_count + 1) * width
                    ]
                    == block
                ):
                    repeat_count += 1
                if repeat_count >= 3:
                    key = (offset, width, repeat_count, sha256(block).hexdigest())
                    occurrences[key].append(sample)
                    offset += repeat_count * width
                else:
                    offset += 1
    candidates: list[dict[str, Any]] = []
    for (offset, width, repeat_count, block_digest), supporting in occurrences.items():
        supporting_ids = {_sample_id(item) for item in supporting}
        counterexamples = [
            item for item in samples if _sample_id(item) not in supporting_ids
        ]
        capture_count = len({item.source.capture_id for item in supporting})
        status = (
            "supported"
            if not counterexamples and capture_count >= 2
            else "candidate"
            if capture_count >= 2
            else "rejected"
        )
        candidates.append(
            {
                "candidate_id": (
                    f"remainder-{offset}-width-{width}-repeat-{repeat_count}"
                ),
                "remainder_offset": offset,
                "absolute_offset": _ABSOLUTE_BODY_OFFSET + offset,
                "block_width": width,
                "repeat_count": repeat_count,
                "block_sha256": block_digest,
                "status": status,
                "supporting_examples": [
                    _example(item, repeat_count, repeat_count) for item in supporting
                ],
                "counterexamples": [
                    _example(item, None, repeat_count) for item in counterexamples
                ],
            }
        )
    candidates.sort(
        key=lambda item: (
            0 if item["status"] == "supported" else 1,
            0 if item["status"] == "candidate" else 1,
            -len(item["supporting_examples"]),
            item["remainder_offset"],
            item["block_width"],
        )
    )
    return {
        "status": _relation_status(candidates),
        "tested_block_widths": list(_REPETITION_WIDTHS),
        "minimum_adjacent_repeat_count": 3,
        "reported_candidate_limit": _MAX_REPETITION_CANDIDATES,
        "candidates": candidates[:_MAX_REPETITION_CANDIDATES],
    }


def _pair_report(
    left: BodyStructureSample,
    right: BodyStructureSample,
) -> dict[str, Any]:
    first_difference = _first_difference(left.remainder, right.remainder)
    return {
        "left_sample_id": _sample_id(left),
        "right_sample_id": _sample_id(right),
        "same_capture": left.source.capture_id == right.source.capture_id,
        "left_capture_id": left.source.capture_id,
        "right_capture_id": right.source.capture_id,
        "left_remainder_length": len(left.remainder),
        "right_remainder_length": len(right.remainder),
        "identical_remainder": left.remainder == right.remainder,
        "first_differing_remainder_offset": first_difference,
        "first_differing_absolute_offset": (
            _ABSOLUTE_BODY_OFFSET + first_difference
            if first_difference is not None
            else None
        ),
        "common_prefix_length": _common_prefix(left.remainder, right.remainder),
        "common_suffix_length": _common_suffix(left.remainder, right.remainder),
        "different_byte_count": _different_byte_count(left.remainder, right.remainder),
        "length_delta": len(right.remainder) - len(left.remainder),
    }


def _repeatability_report(pairs: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "pair_count": len(pairs),
        "identical_pair_count": sum(
            1 for item in pairs if item["identical_remainder"] is True
        ),
        "different_pair_count": sum(
            1 for item in pairs if item["identical_remainder"] is False
        ),
        "pairs": list(pairs),
    }


def _priority_evidence(
    samples: Sequence[BodyStructureSample],
    variants: Sequence[dict[str, Any]],
    pairs: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    cross_capture_variants = [item for item in variants if item["capture_count"] >= 2]
    max_sample_count = max(
        (item["sample_count"] for item in cross_capture_variants),
        default=0,
    )
    max_capture_count = max(
        (item["capture_count"] for item in cross_capture_variants),
        default=0,
    )
    cross_pairs = [item for item in pairs if item["same_capture"] is False]
    max_shared_edges = max(
        (
            item["common_prefix_length"] + item["common_suffix_length"]
            for item in cross_pairs
        ),
        default=0,
    )
    reason = (
        "cross-capture-byte-identical-remainders"
        if cross_capture_variants
        else "cross-capture-common-edge-similarity"
        if cross_pairs
        else "insufficient-cross-capture-pairs"
    )
    return {
        "reason": reason,
        "max_identical_cross_capture_sample_count": max_sample_count,
        "max_identical_cross_capture_capture_count": max_capture_count,
        "max_cross_capture_shared_edge_bytes": max_shared_edges,
        "sample_count": len(samples),
    }


def _group_priority_sort_key(group: dict[str, Any]) -> tuple[int, int, int, str]:
    evidence = group["priority_evidence"]
    return (
        -evidence["max_identical_cross_capture_sample_count"],
        -evidence["max_identical_cross_capture_capture_count"],
        -evidence["max_cross_capture_shared_edge_bytes"],
        group["signature_identity"]["signature_id"],
    )


def _sample_report(item: BodyStructureSample) -> dict[str, Any]:
    return {
        "sample_id": _sample_id(item),
        "capture_id": item.source.capture_id,
        "phase": item.source.phase,
        "timestamp": item.source.timestamp,
        "message_family": item.source.message_family,
        "association": item.source.association,
        "serial": item.source.serial,
        "infoSize": item.source.info_size,
        "derived_total_length": len(item.source.derived_bytes),
        "remainder_length": len(item.remainder),
        "remainder_sha256": item.remainder_sha256,
        "control_transports": list(item.source.control_transports),
    }


def _example(
    item: BodyStructureSample,
    observed_value: Any,
    target_value: Any,
) -> dict[str, Any]:
    return {
        "sample_id": _sample_id(item),
        "capture_id": item.source.capture_id,
        "timestamp": item.source.timestamp,
        "infoSize": item.source.info_size,
        "serial": item.source.serial,
        "derived_total_length": len(item.source.derived_bytes),
        "remainder_length": len(item.remainder),
        "observed_value": observed_value,
        "target_value": target_value,
    }


def _first_group_difference(samples: Sequence[BodyStructureSample]) -> int | None:
    if len(samples) < 2:
        return None
    return min(
        (
            offset
            for left, right in combinations(samples, 2)
            if (offset := _first_difference(left.remainder, right.remainder))
            is not None
        ),
        default=None,
    )


def _common_prefix_all(values: Sequence[bytes]) -> bytes:
    prefix = values[0]
    for value in values[1:]:
        prefix = prefix[: _common_prefix(prefix, value)]
    return prefix


def _common_suffix_all(values: Sequence[bytes]) -> bytes:
    suffix = values[0]
    for value in values[1:]:
        suffix = suffix[len(suffix) - _common_suffix(suffix, value) :]
        if not suffix:
            break
    return suffix


def _first_difference(left: bytes, right: bytes) -> int | None:
    for offset, (left_byte, right_byte) in enumerate(zip(left, right, strict=False)):
        if left_byte != right_byte:
            return offset
    if len(left) != len(right):
        return min(len(left), len(right))
    return None


def _common_prefix(left: bytes, right: bytes) -> int:
    return next(
        (
            offset
            for offset, (left_byte, right_byte) in enumerate(
                zip(left, right, strict=False)
            )
            if left_byte != right_byte
        ),
        min(len(left), len(right)),
    )


def _common_suffix(left: bytes, right: bytes) -> int:
    count = 0
    for left_byte, right_byte in zip(reversed(left), reversed(right), strict=False):
        if left_byte != right_byte:
            break
        count += 1
    return count


def _different_byte_count(left: bytes, right: bytes) -> int:
    return sum(
        left_byte != right_byte
        for left_byte, right_byte in zip_longest(left, right, fillvalue=None)
    )


def _sample_id(item: BodyStructureSample) -> str:
    return sha256(
        (
            f"{item.source.capture_id}|{item.source.timestamp}|"
            f"{item.source.derived_sha256}|{item.remainder_sha256}"
        ).encode()
    ).hexdigest()[:20]


def _inner_sample_id(item: InnerStructureSample) -> str:
    return sha256(
        (
            f"{item.capture_id}|{item.timestamp}|{item.message_family}|"
            f"{item.derived_sha256}"
        ).encode()
    ).hexdigest()[:20]


def _sample_sort_key(item: BodyStructureSample) -> tuple[str, str, str]:
    return item.source.phase, item.source.timestamp, _sample_id(item)


def _distribution(values: Iterable[Any]) -> list[dict[str, Any]]:
    counts = Counter(values)
    return [
        {"value": value, "count": count}
        for value, count in sorted(counts.items(), key=lambda item: repr(item[0]))
    ]
