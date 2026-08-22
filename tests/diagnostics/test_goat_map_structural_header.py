from __future__ import annotations

import base64
from pathlib import Path

import orjson
import pytest

from deebot_client.diagnostics.goat_map_representation import (
    decode_strict_base64_representation,
)
from deebot_client.diagnostics.goat_map_segment_grouping import (
    OpaqueSegmentInput,
    assemble_opaque_segment_set,
)
from deebot_client.diagnostics.goat_map_structural_header import (
    StructuralHeaderInfoSizeMismatchError,
    StructuralHeaderInvariantError,
    StructuralHeaderPrefixError,
    StructuralHeaderTooShortError,
    UnsupportedStructuralFamilyError,
    recognize_structural_header,
)

_GOLDEN_FIXTURE = (
    Path(__file__).parents[1]
    / "fixtures"
    / "goat_map"
    / "onmi_info_representations.json"
)
_PREFIX = bytes.fromhex("5d00000400")
_INVARIANT = bytes.fromhex("002d96c042005e")


def _golden_onmi(label: str) -> tuple[bytes, int]:
    fixtures = orjson.loads(_GOLDEN_FIXTURE.read_bytes())
    fixture = next(item for item in fixtures if item["label"] == label)
    return (
        decode_strict_base64_representation(fixture["original"]),
        fixture["info_size"],
    )


def _observed_shape(
    *,
    info_size: int,
    family_byte: int,
    remainder_length: int,
    seed: int,
) -> bytes:
    remainder = bytes((index * 31 + seed) % 256 for index in range(remainder_length))
    return (
        _PREFIX
        + info_size.to_bytes(4, "little")
        + _INVARIANT
        + bytes([family_byte])
        + remainder
    )


def _grouped_onari(
    *,
    serial: int,
    info_size: int,
    remainder_length: int,
) -> bytes:
    derived = _observed_shape(
        info_size=info_size,
        family_byte=0x14,
        remainder_length=remainder_length,
        seed=serial,
    )
    parts: tuple[bytes, ...] = (
        (derived,) if serial == 1 else (derived[:768], derived[768:])
    )
    assembled = assemble_opaque_segment_set(
        [
            OpaqueSegmentInput(
                batid=f"structural-example-{serial}",
                serial=serial,
                index=index,
                info_size=info_size,
                mid="1",
                type=0 if serial == 2 else -1,
                using=1,
                representation=base64.b64encode(part).decode("ascii"),
            )
            for index, part in enumerate(parts)
        ]
    )
    return assembled.derived_concatenation


def test_known_request_associated_onmi_has_equal_info_size_candidates() -> None:
    derived, info_size = _golden_onmi("immediate-876")

    view = recognize_structural_header(derived, envelope_info_size=info_size)

    assert view.observed_family == "onMI"
    assert view.family_discriminator_raw == 0x11
    assert view.info_size_u16_candidate == 1756
    assert view.info_size_u32_candidate == 1756
    assert view.info_size_candidates_equal is True
    assert view.info_size_u16_matches_envelope is True
    assert view.info_size_u32_matches_envelope is True
    assert view.bytes_7_8_raw == b"\x00\x00"


def test_known_cadence_associated_onmi_preserves_remainder() -> None:
    derived, info_size = _golden_onmi("periodic-52")

    view = recognize_structural_header(derived, envelope_info_size=info_size)

    assert view.observed_family == "onMI"
    assert view.info_size_u16_candidate == 25
    assert view.info_size_u32_candidate == 25
    assert view.info_size_candidates_equal is True
    assert view.remainder == derived[17:]
    assert view.to_bytes() == derived


def test_grouped_request_associated_onari_is_recognized_after_assembly() -> None:
    derived = _grouped_onari(serial=2, info_size=6316, remainder_length=1404)

    view = recognize_structural_header(derived, envelope_info_size=6316)

    assert view.observed_family == "onArI"
    assert view.family_discriminator_raw == 0x14
    assert view.info_size_candidates_equal is True
    assert view.to_bytes() == derived


def test_cadence_serial_one_onari_is_recognized_after_assembly() -> None:
    derived = _grouped_onari(serial=1, info_size=1303, remainder_length=598)

    view = recognize_structural_header(derived, envelope_info_size=1303)

    assert view.observed_family == "onArI"
    assert view.family_discriminator_raw == 0x14
    assert view.remainder == derived[17:]


def test_remainder_round_trip_is_byte_identical_and_uninterpreted() -> None:
    derived = _observed_shape(
        info_size=25,
        family_byte=0x11,
        remainder_length=64,
        seed=91,
    )

    view = recognize_structural_header(derived)

    assert view.prefix == _PREFIX
    assert view.common_invariant_9_15 == _INVARIANT
    assert view.remainder == derived[17:]
    assert view.to_bytes() == derived
    assert view.envelope_info_size is None
    assert view.info_size_u16_matches_envelope is None
    assert view.info_size_u32_matches_envelope is None


def test_wrong_prefix_is_rejected() -> None:
    derived = bytearray(
        _observed_shape(
            info_size=25,
            family_byte=0x11,
            remainder_length=1,
            seed=1,
        )
    )
    derived[0] = 0x00

    with pytest.raises(StructuralHeaderPrefixError, match="structural prefix"):
        recognize_structural_header(bytes(derived))


@pytest.mark.parametrize("length", [0, 1, 16])
def test_too_short_input_is_rejected(length: int) -> None:
    with pytest.raises(StructuralHeaderTooShortError, match="at least 17 bytes"):
        recognize_structural_header(b"\x00" * length)


def test_envelope_info_size_mismatch_is_rejected() -> None:
    derived, _ = _golden_onmi("periodic-52")

    with pytest.raises(
        StructuralHeaderInfoSizeMismatchError,
        match="Neither offset-5 candidate",
    ):
        recognize_structural_header(derived, envelope_info_size=999)


def test_wrong_observed_invariant_is_rejected() -> None:
    derived = bytearray(
        _observed_shape(
            info_size=25,
            family_byte=0x11,
            remainder_length=1,
            seed=1,
        )
    )
    derived[12] ^= 0xFF

    with pytest.raises(StructuralHeaderInvariantError, match=r"bytes 9\.\.15"):
        recognize_structural_header(bytes(derived))


def test_unknown_family_discriminator_is_rejected() -> None:
    derived = _observed_shape(
        info_size=25,
        family_byte=0x99,
        remainder_length=1,
        seed=1,
    )

    with pytest.raises(
        UnsupportedStructuralFamilyError,
        match="family discriminator: 0x99",
    ):
        recognize_structural_header(derived)


def test_nonzero_bytes_7_8_keep_u16_and_u32_candidates_distinct() -> None:
    offset_five = b"\x34\x12\x78\x56"
    derived = _PREFIX + offset_five + _INVARIANT + b"\x11opaque"

    view = recognize_structural_header(derived, envelope_info_size=0x1234)

    assert view.bytes_7_8_raw == b"\x78\x56"
    assert view.info_size_u16_candidate == 0x1234
    assert view.info_size_u32_candidate == 0x56781234
    assert view.info_size_candidates_equal is False
    assert view.info_size_u16_matches_envelope is True
    assert view.info_size_u32_matches_envelope is False
    assert view.to_bytes() == derived

    u32_view = recognize_structural_header(
        derived,
        envelope_info_size=0x56781234,
    )
    assert u32_view.info_size_u16_matches_envelope is False
    assert u32_view.info_size_u32_matches_envelope is True
