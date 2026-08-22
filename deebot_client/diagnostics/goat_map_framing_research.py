"""Non-semantic framing research for proven GOAT representation bytes."""

from __future__ import annotations

from collections import Counter
import math
import struct
from typing import Any
import zlib

from .goat_map_representation import preserve_onmi_info_representation

_HEADER_SCAN_BYTES = 16
_FLOAT_SCAN_BYTES = 21


def analyze_onmi_framing_pair(
    first_original: str,
    second_original: str,
    *,
    first_info_size: int | None = None,
    second_info_size: int | None = None,
) -> dict[str, Any]:
    """Compare two Base64-derived byte strings without assigning field meaning."""
    first = preserve_onmi_info_representation(first_original)
    second = preserve_onmi_info_representation(second_original)
    first_bytes = first.decoded
    second_bytes = second.decoded
    shared_prefix = _common_prefix(first_bytes, second_bytes)
    shared_suffix = _common_suffix(first_bytes, second_bytes, shared_prefix)
    integer_windows = _integer_windows(
        first_bytes,
        second_bytes,
        first_info_size=first_info_size,
        second_info_size=second_info_size,
    )
    return {
        "analysis_kind": "opaque-framing-research/v1",
        "representation_decoding": "strict-base64-only",
        "semantic_map_decoding": False,
        "framing_parser_implemented": False,
        "first": {
            "original_sha256": first.original_sha256,
            "original_byte_length": len(first.original.encode()),
            "decoded_sha256": first.decoded_sha256,
            "decoded_byte_length": len(first_bytes),
            "leading_bytes_hex": first_bytes[:16].hex(),
            "trailing_bytes_hex": first_bytes[-16:].hex(),
        },
        "second": {
            "original_sha256": second.original_sha256,
            "original_byte_length": len(second.original.encode()),
            "decoded_sha256": second.decoded_sha256,
            "decoded_byte_length": len(second_bytes),
            "leading_bytes_hex": second_bytes[:16].hex(),
            "trailing_bytes_hex": second_bytes[-16:].hex(),
        },
        "common_prefix_bytes": shared_prefix,
        "common_suffix_bytes": shared_suffix,
        "first_differing_offset": (
            shared_prefix if first_bytes != second_bytes else None
        ),
        "difference_ranges_within_shorter": _difference_ranges(
            first_bytes,
            second_bytes,
        ),
        "header_integer_windows": integer_windows,
        "consistent_length_field_candidates": [
            candidate
            for candidate in integer_windows
            if candidate["consistent_length_relations"]
        ],
        "metadata_field_candidates": [
            candidate
            for candidate in integer_windows
            if candidate["metadata_relations"]
        ],
        "float32_candidates": _float32_candidates(first_bytes, second_bytes),
        "trailer_checksum_matches": {
            "first": _trailer_checksum_matches(first_bytes),
            "second": _trailer_checksum_matches(second_bytes),
        },
        "repetition": {
            "first": _repetition_summary(first_bytes),
            "second": _repetition_summary(second_bytes),
        },
        "interpretation_guard": (
            "All values are framing candidates only; no integer, float, boundary, "
            "trailer, or repeated block has map semantics."
        ),
    }


def _common_prefix(first: bytes, second: bytes) -> int:
    count = 0
    for left, right in zip(first, second, strict=False):
        if left != right:
            break
        count += 1
    return count


def _common_suffix(first: bytes, second: bytes, shared_prefix: int) -> int:
    count = 0
    remaining = min(len(first), len(second)) - shared_prefix
    while count < remaining and first[-count - 1] == second[-count - 1]:
        count += 1
    return count


def _difference_ranges(first: bytes, second: bytes) -> list[dict[str, int]]:
    differing = [
        offset
        for offset, (left, right) in enumerate(zip(first, second, strict=False))
        if left != right
    ]
    if not differing:
        return []
    ranges: list[dict[str, int]] = []
    start = previous = differing[0]
    for offset in differing[1:]:
        if offset != previous + 1:
            ranges.append({"start": start, "end_exclusive": previous + 1})
            start = offset
        previous = offset
    ranges.append({"start": start, "end_exclusive": previous + 1})
    return ranges


def _integer_windows(
    first: bytes,
    second: bytes,
    *,
    first_info_size: int | None,
    second_info_size: int | None,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    scan_length = min(_HEADER_SCAN_BYTES, len(first), len(second))
    for width in (1, 2, 4):
        for offset in range(scan_length - width + 1):
            for byte_order in ("little", "big") if width > 1 else ("little",):
                first_value = int.from_bytes(
                    first[offset : offset + width],
                    byteorder=byte_order,
                )
                second_value = int.from_bytes(
                    second[offset : offset + width],
                    byteorder=byte_order,
                )
                first_relations = _length_relations(
                    first_value,
                    decoded_length=len(first),
                    original_length=_base64_length(len(first)),
                    offset=offset,
                    width=width,
                )
                second_relations = _length_relations(
                    second_value,
                    decoded_length=len(second),
                    original_length=_base64_length(len(second)),
                    offset=offset,
                    width=width,
                )
                metadata_relations: list[str] = []
                if (
                    first_info_size is not None
                    and second_info_size is not None
                    and first_value == first_info_size
                    and second_value == second_info_size
                ):
                    metadata_relations.append("envelope_infoSize")
                candidates.append(
                    {
                        "offset": offset,
                        "width": width,
                        "byte_order": byte_order,
                        "first_value": first_value,
                        "second_value": second_value,
                        "first_length_relations": first_relations,
                        "second_length_relations": second_relations,
                        "consistent_length_relations": sorted(
                            set(first_relations) & set(second_relations)
                        ),
                        "metadata_relations": metadata_relations,
                    }
                )
    return candidates


def _base64_length(decoded_length: int) -> int:
    return ((decoded_length + 2) // 3) * 4


def _length_relations(
    value: int,
    *,
    decoded_length: int,
    original_length: int,
    offset: int,
    width: int,
) -> list[str]:
    relations = {
        "decoded_total": decoded_length,
        "base64_total": original_length,
        "decoded_remaining_after_field": decoded_length - offset - width,
        "decoded_remaining_from_field": decoded_length - offset,
    }
    for header_length in range(_HEADER_SCAN_BYTES + 1):
        relations[f"decoded_after_header_{header_length}"] = (
            decoded_length - header_length
        )
    return sorted(name for name, expected in relations.items() if value == expected)


def _float32_candidates(first: bytes, second: bytes) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    scan_length = min(_FLOAT_SCAN_BYTES, len(first), len(second))
    for offset in range(scan_length - 3):
        for byte_order, prefix in (("little", "<"), ("big", ">")):
            first_value = struct.unpack_from(f"{prefix}f", first, offset)[0]
            second_value = struct.unpack_from(f"{prefix}f", second, offset)[0]
            if not (_plausible_float(first_value) and _plausible_float(second_value)):
                continue
            result.append(
                {
                    "offset": offset,
                    "byte_order": byte_order,
                    "first_value": first_value,
                    "second_value": second_value,
                    "same_bits_in_both": (
                        first[offset : offset + 4] == second[offset : offset + 4]
                    ),
                }
            )
    return result


def _plausible_float(value: float) -> bool:
    if not math.isfinite(value):
        return False
    magnitude = abs(value)
    return value == 0.0 or 1e-4 <= magnitude <= 1e6


def _trailer_checksum_matches(raw: bytes) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for width in (1, 2, 4):
        if len(raw) <= width:
            continue
        body = raw[:-width]
        mask = (1 << (width * 8)) - 1
        checksums = {
            "sum": sum(body) & mask,
            "xor": _xor(body) & mask,
            "crc32": zlib.crc32(body) & mask,
            "adler32": zlib.adler32(body) & mask,
        }
        for byte_order in ("little", "big") if width > 1 else ("little",):
            trailer = int.from_bytes(raw[-width:], byteorder=byte_order)
            for algorithm, calculated in checksums.items():
                if trailer == calculated:
                    matches.append(
                        {
                            "width": width,
                            "byte_order": byte_order,
                            "algorithm": algorithm,
                            "value": trailer,
                        }
                    )
    return matches


def _xor(raw: bytes) -> int:
    result = 0
    for byte in raw:
        result ^= byte
    return result


def _repetition_summary(raw: bytes) -> dict[str, Any]:
    return {
        "longest_identical_byte_run": _longest_identical_byte_run(raw),
        "fixed_width_blocks": [
            _fixed_width_block_summary(raw, width) for width in (2, 4, 8, 16)
        ],
        "period_match_fractions": [
            {
                "period": period,
                "match_fraction": _period_match_fraction(raw, period),
            }
            for period in range(1, min(16, len(raw) - 1) + 1)
        ],
    }


def _longest_identical_byte_run(raw: bytes) -> int:
    longest = current = 0
    previous: int | None = None
    for byte in raw:
        current = current + 1 if byte == previous else 1
        longest = max(longest, current)
        previous = byte
    return longest


def _fixed_width_block_summary(raw: bytes, width: int) -> dict[str, int]:
    blocks = [
        raw[offset : offset + width] for offset in range(0, len(raw) - width + 1, width)
    ]
    counts = Counter(blocks)
    return {
        "width": width,
        "complete_block_count": len(blocks),
        "unique_block_count": len(counts),
        "repeated_block_value_count": sum(count > 1 for count in counts.values()),
        "maximum_repetition_count": max(counts.values(), default=0),
    }


def _period_match_fraction(raw: bytes, period: int) -> float:
    comparisons = len(raw) - period
    if comparisons <= 0:
        return 0.0
    matches = sum(
        raw[index] == raw[index - period] for index in range(period, len(raw))
    )
    return matches / comparisons
