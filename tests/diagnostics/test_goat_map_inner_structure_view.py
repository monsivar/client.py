from __future__ import annotations

from pathlib import Path

import orjson
import pytest

from deebot_client.diagnostics.goat_map_inner_structure_view import (
    InnerStructureFamilyMismatchError,
    InnerStructureViewTooShortError,
    recognize_inner_structure,
)
from deebot_client.diagnostics.goat_map_representation import (
    decode_strict_base64_representation,
)
from deebot_client.diagnostics.goat_map_structural_header import (
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
_ONARI_SERIAL_1_SIGNATURE = bytes.fromhex("63d1dceaf6490fc728b85a4e13e18bae5c")
_ONARI_SERIAL_2_SIGNATURE = bytes.fromhex("b4fc81d4375de7a0f636f001dc016fe0ca")


def _golden_onmi() -> tuple[tuple[bytes, int], ...]:
    fixtures = orjson.loads(_GOLDEN_FIXTURE.read_bytes())
    return tuple(
        (
            decode_strict_base64_representation(item["original"]),
            item["info_size"],
        )
        for item in fixtures
    )


def _framed(
    *,
    family_byte: int,
    info_size: int,
    signature: bytes,
    remainder: bytes,
) -> bytes:
    assert len(signature) == 17
    return (
        _PREFIX
        + info_size.to_bytes(4, "little")
        + _INVARIANT
        + bytes([family_byte])
        + signature
        + remainder
    )


def test_both_onmi_forms_map_to_same_observed_context_class() -> None:
    views = []
    for derived, info_size in _golden_onmi():
        header = recognize_structural_header(
            derived,
            envelope_info_size=info_size,
        )
        views.append(recognize_inner_structure(header))

    assert {view.observed_context_class for view in views} == {"observed-onMI"}
    assert views[0].context_signature_raw != views[1].context_signature_raw
    assert all(view.envelope_serial is None for view in views)


def test_observed_b4_onari_signature_preserves_envelope_serial_separately() -> None:
    derived = _framed(
        family_byte=0x14,
        info_size=6316,
        signature=_ONARI_SERIAL_2_SIGNATURE,
        remainder=b"opaque-request-remainder",
    )
    header = recognize_structural_header(derived, envelope_info_size=6316)

    view = recognize_inner_structure(header, envelope_serial=2)

    assert view.observed_context_class == "observed-onArI-b4-signature"
    assert view.context_signature_raw == _ONARI_SERIAL_2_SIGNATURE
    assert view.envelope_serial == 2


def test_observed_63_onari_signature_preserves_envelope_serial_separately() -> None:
    derived = _framed(
        family_byte=0x14,
        info_size=1303,
        signature=_ONARI_SERIAL_1_SIGNATURE,
        remainder=b"opaque-cadence-remainder",
    )
    header = recognize_structural_header(derived, envelope_info_size=1303)

    view = recognize_inner_structure(header, envelope_serial=1)

    assert view.observed_context_class == "observed-onArI-63-signature"
    assert view.context_signature_raw == _ONARI_SERIAL_1_SIGNATURE
    assert view.envelope_serial == 1


def test_remainder_and_original_round_trip_are_byte_identical() -> None:
    remainder = bytes(range(64))
    derived = _framed(
        family_byte=0x14,
        info_size=1303,
        signature=_ONARI_SERIAL_1_SIGNATURE,
        remainder=remainder,
    )
    header = recognize_structural_header(derived, envelope_info_size=1303)

    view = recognize_inner_structure(header, envelope_serial=1)

    assert view.remainder == remainder
    assert view.original_bytes == derived
    assert view.to_bytes() == derived
    assert view.structural_header is header


def test_unknown_context_signature_is_preserved_without_guessing() -> None:
    signature = bytes.fromhex("0102030405060708090a0b0c0d0e0f1011")
    remainder = b"opaque-future-data"
    derived = _framed(
        family_byte=0x11,
        info_size=25,
        signature=signature,
        remainder=remainder,
    )
    header = recognize_structural_header(derived, envelope_info_size=25)

    view = recognize_inner_structure(header, envelope_serial=99)

    assert view.observed_context_class == "unknown"
    assert view.context_signature_raw == signature
    assert view.envelope_serial == 99
    assert view.remainder == remainder
    assert view.to_bytes() == derived


def test_63_signature_does_not_imply_envelope_cardinality() -> None:
    derived = _framed(
        family_byte=0x14,
        info_size=1303,
        signature=_ONARI_SERIAL_1_SIGNATURE,
        remainder=b"opaque",
    )
    header = recognize_structural_header(derived, envelope_info_size=1303)

    view = recognize_inner_structure(header, envelope_serial=2)

    assert view.observed_context_class == "observed-onArI-63-signature"
    assert view.envelope_serial == 2


@pytest.mark.parametrize("envelope_serial", [2, 3])
def test_b4_signature_does_not_imply_envelope_cardinality(
    envelope_serial: int,
) -> None:
    derived = _framed(
        family_byte=0x14,
        info_size=6316,
        signature=_ONARI_SERIAL_2_SIGNATURE,
        remainder=b"opaque",
    )
    header = recognize_structural_header(derived, envelope_info_size=6316)

    view = recognize_inner_structure(header, envelope_serial=envelope_serial)

    assert view.observed_context_class == "observed-onArI-b4-signature"
    assert view.context_signature_raw == _ONARI_SERIAL_2_SIGNATURE
    assert view.envelope_serial == envelope_serial


def test_offset_34_variation_does_not_change_context_classification() -> None:
    views = []
    for first_remainder_byte in (0xE6, 0xF9):
        derived = _framed(
            family_byte=0x14,
            info_size=1303,
            signature=_ONARI_SERIAL_1_SIGNATURE,
            remainder=bytes([first_remainder_byte]) + b"opaque",
        )
        header = recognize_structural_header(derived, envelope_info_size=1303)
        views.append(recognize_inner_structure(header, envelope_serial=1))

    assert {view.observed_context_class for view in views} == {
        "observed-onArI-63-signature"
    }
    assert {view.remainder[0] for view in views} == {0xE6, 0xF9}


def test_known_signature_conflicting_with_outer_family_is_explicit_mismatch() -> None:
    derived = _framed(
        family_byte=0x11,
        info_size=25,
        signature=_ONARI_SERIAL_1_SIGNATURE,
        remainder=b"opaque",
    )
    header = recognize_structural_header(derived, envelope_info_size=25)

    with pytest.raises(InnerStructureFamilyMismatchError, match="outer family"):
        recognize_inner_structure(header, envelope_serial=1)


def test_valid_outer_frame_too_short_for_inner_view_is_distinct_error() -> None:
    derived = _PREFIX + (25).to_bytes(4, "little") + _INVARIANT + b"\x11short"
    header = recognize_structural_header(derived, envelope_info_size=25)

    with pytest.raises(InnerStructureViewTooShortError, match=r"offsets 17\.\.33"):
        recognize_inner_structure(header)
