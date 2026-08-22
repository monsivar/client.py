from __future__ import annotations

import base64
from dataclasses import replace
from hashlib import sha256

import pytest

from deebot_client.diagnostics.goat_map_segment_grouping import (
    DuplicateSegmentIndexError,
    IncompleteSegmentGroupError,
    InvalidSegmentRepresentationError,
    MixedSegmentIdentityError,
    OpaqueSegmentInput,
    assemble_opaque_segment_set,
    group_opaque_segment_sets,
)


def _representation(decoded_length: int, seed: int) -> str:
    value = bytes((index * 73 + seed) % 256 for index in range(decoded_length))
    return base64.b64encode(value).decode("ascii")


def _segment(
    *,
    index: int,
    representation: str,
    batid: str = "opaque-batch-a",
    serial: int = 2,
    info_size: int = 1756,
    mid: str = "1",
    segment_type: int = 0,
    using: int = 1,
) -> OpaqueSegmentInput:
    return OpaqueSegmentInput(
        batid=batid,
        serial=serial,
        index=index,
        info_size=info_size,
        mid=mid,
        type=segment_type,
        using=using,
        representation=representation,
    )


@pytest.mark.parametrize("second_decoded_length", [653, 672])
def test_complete_serial_two_structures_preserve_and_assemble(
    second_decoded_length: int,
) -> None:
    first_representation = _representation(768, 11)
    second_representation = _representation(second_decoded_length, 29)
    assert len(first_representation) == 1024
    assert len(second_representation) in {872, 896}

    result = assemble_opaque_segment_set(
        [
            _segment(index=0, representation=first_representation),
            _segment(index=1, representation=second_representation),
        ]
    )

    expected = base64.b64decode(first_representation) + base64.b64decode(
        second_representation
    )
    assert [segment.index for segment in result.segments] == [0, 1]
    assert result.segments[0].original_representation == first_representation
    assert result.segments[0].original_representation_length == 1024
    assert (
        result.segments[0].original_representation_sha256
        == sha256(first_representation.encode()).hexdigest()
    )
    assert result.segments[0].derived_byte_length == 768
    assert result.derived_concatenation == expected
    assert result.derived_concatenation_length == 768 + second_decoded_length
    assert result.derived_concatenation_sha256 == sha256(expected).hexdigest()
    assert result.identity.info_size == 1756


@pytest.mark.parametrize("representation_length", [780, 796, 820, 840])
def test_serial_one_accepts_observed_variable_lengths(
    representation_length: int,
) -> None:
    decoded_length = representation_length // 4 * 3
    if representation_length % 4 == 0 and representation_length in {780, 796}:
        decoded_length -= 1
    representation = _representation(decoded_length, 43)
    assert len(representation) == representation_length

    result = assemble_opaque_segment_set(
        [
            _segment(
                index=0,
                serial=1,
                info_size=25,
                representation=representation,
            )
        ]
    )

    assert [segment.index for segment in result.segments] == [0]
    assert result.segments[0].original_representation_length == representation_length


def test_reversed_arrival_order_is_sorted_by_index() -> None:
    first = _segment(index=0, representation=_representation(768, 7))
    second = _segment(index=1, representation=_representation(653, 9))

    result = assemble_opaque_segment_set([second, first])

    assert [segment.index for segment in result.segments] == [0, 1]
    assert result.derived_concatenation == base64.b64decode(
        first.representation
    ) + base64.b64decode(second.representation)


def test_duplicate_index_is_explicit_error() -> None:
    representation = _representation(768, 3)
    with pytest.raises(DuplicateSegmentIndexError, match="Duplicate segment index 0"):
        assemble_opaque_segment_set(
            [
                _segment(index=0, representation=representation),
                _segment(index=0, representation=representation),
            ]
        )


def test_missing_index_is_explicit_incomplete_error() -> None:
    with pytest.raises(IncompleteSegmentGroupError) as error:
        assemble_opaque_segment_set(
            [_segment(index=0, representation=_representation(768, 5))]
        )

    assert error.value.missing == (1,)
    assert error.value.unexpected == ()


@pytest.mark.parametrize(
    ("field", "other"),
    [
        ("batid", "opaque-batch-b"),
        ("serial", 3),
        ("info_size", 999),
        ("mid", "2"),
        ("type", -1),
        ("using", 0),
    ],
)
def test_one_assembly_rejects_mixed_envelope_identity(
    field: str,
    other: str | int,
) -> None:
    first = _segment(index=0, representation=_representation(768, 13))
    second = _segment(index=1, representation=_representation(653, 17))
    if field == "batid":
        assert isinstance(other, str)
        second = replace(second, batid=other)
    elif field == "serial":
        assert isinstance(other, int)
        second = replace(second, serial=other)
    elif field == "info_size":
        second = replace(second, info_size=other)
    elif field == "mid":
        second = replace(second, mid=other)
    elif field == "type":
        second = replace(second, type=other)
    else:
        second = replace(second, using=other)

    with pytest.raises(MixedSegmentIdentityError):
        assemble_opaque_segment_set([first, second])


def test_time_near_pairs_with_different_batid_are_never_merged() -> None:
    segments = [
        _segment(index=0, batid="batch-a", representation=_representation(768, 1)),
        _segment(index=1, batid="batch-a", representation=_representation(653, 2)),
        _segment(index=0, batid="batch-b", representation=_representation(768, 3)),
        _segment(index=1, batid="batch-b", representation=_representation(672, 4)),
    ]

    groups = group_opaque_segment_sets(segments)

    assert len(groups) == 2
    assert [group.identity.batid for group in groups] == ["batch-a", "batch-b"]
    assert [[segment.index for segment in group.segments] for group in groups] == [
        [0, 1],
        [0, 1],
    ]


def test_p2_02_like_zero_one_zero_one_is_two_envelope_groups() -> None:
    segments = [
        _segment(index=0, batid="first", representation=_representation(768, 31)),
        _segment(index=1, batid="first", representation=_representation(653, 32)),
        _segment(index=0, batid="second", representation=_representation(768, 33)),
        _segment(index=1, batid="second", representation=_representation(653, 34)),
    ]

    groups = group_opaque_segment_sets(segments)

    assert [(group.identity.batid, len(group.segments)) for group in groups] == [
        ("first", 2),
        ("second", 2),
    ]


def test_noncanonical_segment_representation_is_rejected_explicitly() -> None:
    with pytest.raises(InvalidSegmentRepresentationError) as error:
        assemble_opaque_segment_set(
            [
                _segment(
                    index=0,
                    serial=1,
                    representation="AB==",
                )
            ]
        )

    assert isinstance(error.value.__cause__, ValueError)
