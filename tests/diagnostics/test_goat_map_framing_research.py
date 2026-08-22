from __future__ import annotations

import base64
from pathlib import Path

import orjson

from deebot_client.diagnostics.goat_map_framing_research import (
    analyze_onmi_framing_pair,
)

_GOLDEN_FIXTURE = (
    Path(__file__).parents[1]
    / "fixtures"
    / "goat_map"
    / "onmi_info_representations.json"
)


def _encoded_frame(payload: bytes) -> str:
    body = b"HDR" + bytes([len(payload) + 1]) + payload
    framed = body + bytes([sum(body) & 0xFF])
    return base64.b64encode(framed).decode()


def test_candidate_analyzer_can_detect_consistent_length_and_checksum() -> None:
    report = analyze_onmi_framing_pair(
        _encoded_frame(b"abcde"),
        _encoded_frame(b"abcdefgh"),
    )

    candidate = next(
        item
        for item in report["consistent_length_field_candidates"]
        if item["offset"] == 3 and item["width"] == 1
    )
    assert "decoded_remaining_after_field" in candidate["consistent_length_relations"]
    assert report["trailer_checksum_matches"]["first"] == [
        {
            "width": 1,
            "byte_order": "little",
            "algorithm": "sum",
            "value": 211,
        }
    ]
    assert report["framing_parser_implemented"] is False
    assert report["semantic_map_decoding"] is False


def test_golden_pair_exposes_offset_five_candidate_without_semantics() -> None:
    fixtures = orjson.loads(_GOLDEN_FIXTURE.read_bytes())
    report = analyze_onmi_framing_pair(
        fixtures[0]["original"],
        fixtures[1]["original"],
        first_info_size=fixtures[0]["info_size"],
        second_info_size=fixtures[1]["info_size"],
    )

    assert report["common_prefix_bytes"] == 5
    assert report["common_suffix_bytes"] == 1
    assert report["first_differing_offset"] == 5
    candidate = next(
        item
        for item in report["header_integer_windows"]
        if item["offset"] == 5 and item["width"] == 2 and item["byte_order"] == "little"
    )
    assert candidate["first_value"] == 0x0019
    assert candidate["second_value"] == 0x06DC
    assert candidate["consistent_length_relations"] == []
    assert candidate["metadata_relations"] == ["envelope_infoSize"]
    assert [
        (item["offset"], item["width"], item["byte_order"])
        for item in report["metadata_field_candidates"]
    ] == [(5, 2, "little"), (5, 4, "little")]

    float_candidate = next(
        item
        for item in report["float32_candidates"]
        if item["offset"] == 10 and item["byte_order"] == "little"
    )
    assert float_candidate["same_bits_in_both"] is True
    assert float_candidate["first_value"] == float_candidate["second_value"]
