from __future__ import annotations

import orjson

from deebot_client.diagnostics.goat_map_three_state import analyze_three_state_bytes


def test_equal_length_absolute_classification_covers_all_five_classes() -> None:
    report = analyze_three_state_bytes(
        bytes((0, 1, 2, 3, 4, 5)),
        bytes((0, 9, 2, 3, 8, 6)),
        bytes((0, 1, 9, 3, 8, 7)),
        representation="synthetic",
    )

    totals = report["absolute_offset_comparison"]["classification_totals"]
    assert totals == {
        "invariant": 2,
        "merge-specific": 1,
        "persistent-post-edit": 1,
        "state-or-operation-sensitive": 1,
        "topology-reversed": 1,
    }


def test_variable_length_alignment_preserves_gaps_and_round_trip() -> None:
    report = analyze_three_state_bytes(
        b"prefix-body",
        b"prefix-X-body",
        b"prefix-body",
        representation="synthetic",
    )

    assert report["whole_value_classification"] == "topology-reversed"
    spans = report["pairwise_diffs"]["A_to_B"]["spans"]
    assert [item["operation"] for item in spans] == ["equal", "insert", "equal"]
    assert spans[1]["left"]["length"] == 0
    assert spans[1]["right"]["length"] == 2
    assert spans[0]["left"]["sha256"] == spans[0]["right"]["sha256"]
    assert spans[2]["left"]["sha256"] == spans[2]["right"]["sha256"]
    assert report["alignment"]["classification_totals"]["topology-reversed"] == 2


def test_analysis_is_deterministic_and_contains_no_input_value() -> None:
    canary = b"SECRET-CANARY-OPAQUE-VALUE"
    args = (canary, canary + b"-B", canary + b"-C")
    first = analyze_three_state_bytes(*args, representation="synthetic")
    second = analyze_three_state_bytes(*args, representation="synthetic")

    assert first == second
    serialized = orjson.dumps(first, option=orjson.OPT_SORT_KEYS)
    assert canary not in serialized
    assert first["states"]["A"]["length"] == len(canary)


def test_stable_internal_islands_require_four_bytes() -> None:
    report = analyze_three_state_bytes(
        b"stable-AAAA-tail",
        b"stable-BBBB-tail",
        b"stable-CCCC-tail",
        representation="synthetic",
    )

    islands = report["alignment"]["stable_internal_islands"]
    assert [item["states"]["A"]["length"] for item in islands] == [7, 5]
    assert all(item["classification"] == "invariant" for item in islands)
