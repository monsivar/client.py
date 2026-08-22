"""Minimal structural view of the observed GOAT framing family."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

_OBSERVED_PREFIX = bytes.fromhex("5d00000400")
_OBSERVED_INVARIANT_9_15 = bytes.fromhex("002d96c042005e")
_MINIMUM_LENGTH = 17

type ObservedStructuralFamily = Literal["onMI", "onArI"]


class StructuralHeaderError(ValueError):
    """Base error for bytes outside the observed structural contract."""


class StructuralHeaderTooShortError(StructuralHeaderError):
    """The input cannot contain the complete observed structural prefix."""


class StructuralHeaderPrefixError(StructuralHeaderError):
    """Bytes 0..4 do not match the observed prefix."""


class StructuralHeaderInfoSizeMismatchError(StructuralHeaderError):
    """Neither offset-5 integer candidate matches envelope ``infoSize``."""


class StructuralHeaderInvariantError(StructuralHeaderError):
    """Bytes 9..15 do not match the observed cross-family invariant."""


class UnsupportedStructuralFamilyError(StructuralHeaderError):
    """Byte 16 is not an observed family value."""


@dataclass(frozen=True, slots=True)
class StructuralHeaderView:
    """A lossless view of only the documented structural byte ranges."""

    original_bytes: bytes
    prefix: bytes
    info_size_u16_candidate: int
    info_size_u32_candidate: int
    info_size_candidates_equal: bool
    bytes_7_8_raw: bytes
    common_invariant_9_15: bytes
    family_discriminator_raw: int
    observed_family: ObservedStructuralFamily
    remainder: bytes
    envelope_info_size: int | None
    info_size_u16_matches_envelope: bool | None
    info_size_u32_matches_envelope: bool | None

    def to_bytes(self) -> bytes:
        """Return the original uninterpreted bytes byte-for-byte."""
        return self.original_bytes


def recognize_structural_header(
    data: bytes,
    *,
    envelope_info_size: int | None = None,
) -> StructuralHeaderView:
    """Validate and expose only the observed structural framing ranges."""
    if len(data) < _MINIMUM_LENGTH:
        message = f"Structural header requires at least {_MINIMUM_LENGTH} bytes"
        raise StructuralHeaderTooShortError(message)

    prefix = data[0:5]
    if prefix != _OBSERVED_PREFIX:
        message = f"Unsupported structural prefix: {prefix.hex()}"
        raise StructuralHeaderPrefixError(message)

    invariant = data[9:16]
    if invariant != _OBSERVED_INVARIANT_9_15:
        message = f"Unsupported bytes 9..15: {invariant.hex()}"
        raise StructuralHeaderInvariantError(message)

    family_discriminator = data[16]
    observed_family = _observed_family(family_discriminator)
    info_size_u16 = int.from_bytes(data[5:7], "little")
    info_size_u32 = int.from_bytes(data[5:9], "little")
    u16_matches: bool | None = None
    u32_matches: bool | None = None
    if envelope_info_size is not None:
        if isinstance(envelope_info_size, bool) or not isinstance(
            envelope_info_size, int
        ):
            raise TypeError("envelope_info_size must be an integer or None")
        u16_matches = info_size_u16 == envelope_info_size
        u32_matches = info_size_u32 == envelope_info_size
        if not u16_matches and not u32_matches:
            message = (
                "Neither offset-5 candidate matches envelope infoSize: "
                f"envelope={envelope_info_size}, u16={info_size_u16}, "
                f"u32={info_size_u32}"
            )
            raise StructuralHeaderInfoSizeMismatchError(message)

    return StructuralHeaderView(
        original_bytes=data,
        prefix=prefix,
        info_size_u16_candidate=info_size_u16,
        info_size_u32_candidate=info_size_u32,
        info_size_candidates_equal=info_size_u16 == info_size_u32,
        bytes_7_8_raw=data[7:9],
        common_invariant_9_15=invariant,
        family_discriminator_raw=family_discriminator,
        observed_family=observed_family,
        remainder=data[17:],
        envelope_info_size=envelope_info_size,
        info_size_u16_matches_envelope=u16_matches,
        info_size_u32_matches_envelope=u32_matches,
    )


def _observed_family(value: int) -> ObservedStructuralFamily:
    if value == 0x11:
        return "onMI"
    if value == 0x14:
        return "onArI"
    message = f"Unsupported observed family discriminator: 0x{value:02x}"
    raise UnsupportedStructuralFamilyError(message)
