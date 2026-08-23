"""Pure structural grouping for opaque onArI segments."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from .goat_map_representation import (
    RepresentationDecodeError,
    decode_strict_base64_representation,
)

type EnvelopeValue = str | int
type SegmentCardinalityValue = str | int


class SegmentGroupingError(ValueError):
    """Base error for invalid opaque segment-set structure."""


class EmptySegmentGroupError(SegmentGroupingError):
    """No segment was supplied for assembly."""


class InvalidSegmentEnvelopeError(SegmentGroupingError):
    """An envelope field is outside the observed structural contract."""


class InvalidSegmentRepresentationError(SegmentGroupingError):
    """A segment representation is not strict canonical Base64."""


class MixedSegmentIdentityError(SegmentGroupingError):
    """Segments passed to one assembly have different envelope identities."""


class DuplicateSegmentIndexError(SegmentGroupingError):
    """One envelope identity contains the same index more than once."""


class IncompleteSegmentGroupError(SegmentGroupingError):
    """An envelope identity does not contain exactly ``0..serial-1``."""

    def __init__(
        self, *, missing: tuple[int, ...], unexpected: tuple[int, ...]
    ) -> None:
        self.missing = missing
        self.unexpected = unexpected
        super().__init__(
            f"Incomplete segment index set: missing={missing}, unexpected={unexpected}"
        )


@dataclass(frozen=True, slots=True)
class OpaqueSegmentInput:
    """One uninterpreted segment and its observed envelope identity."""

    batid: str
    serial: SegmentCardinalityValue
    index: SegmentCardinalityValue
    info_size: EnvelopeValue
    mid: EnvelopeValue
    type: EnvelopeValue
    using: EnvelopeValue
    representation: str


@dataclass(frozen=True, slots=True)
class OpaqueSegmentSetIdentity:
    """Envelope fields that identify one observed segment set."""

    batid: str
    serial: int
    info_size: EnvelopeValue
    mid: EnvelopeValue
    type: EnvelopeValue
    using: EnvelopeValue


@dataclass(frozen=True, slots=True)
class PreservedOpaqueSegment:
    """Original representation and separately derived uninterpreted bytes."""

    index: int
    original_representation: str
    original_representation_length: int
    original_representation_sha256: str
    derived_bytes: bytes
    derived_byte_length: int
    derived_sha256: str


@dataclass(frozen=True, slots=True)
class OpaqueSegmentSet:
    """A complete, index-ordered opaque segment assembly."""

    identity: OpaqueSegmentSetIdentity
    segments: tuple[PreservedOpaqueSegment, ...]
    derived_concatenation: bytes
    derived_concatenation_length: int
    derived_concatenation_sha256: str


def assemble_opaque_segment_set(
    segments: list[OpaqueSegmentInput] | tuple[OpaqueSegmentInput, ...],
) -> OpaqueSegmentSet:
    """Validate and assemble exactly one complete envelope identity."""
    if not segments:
        raise EmptySegmentGroupError("At least one segment is required")

    first_identity = _identity(segments[0])
    preserved_by_index: dict[int, PreservedOpaqueSegment] = {}
    for segment in segments:
        identity = _identity(segment)
        if identity != first_identity:
            raise MixedSegmentIdentityError(
                "One assembly cannot mix batid, serial, infoSize, mid, type, or using"
            )
        index = normalize_segment_cardinality(
            "index",
            segment.index,
            allow_zero=True,
        )
        if index in preserved_by_index:
            message = f"Duplicate segment index {index} for one envelope identity"
            raise DuplicateSegmentIndexError(message)
        preserved_by_index[index] = _preserve_segment(segment, index=index)

    expected = set(range(first_identity.serial))
    observed = set(preserved_by_index)
    if observed != expected:
        raise IncompleteSegmentGroupError(
            missing=tuple(sorted(expected - observed)),
            unexpected=tuple(sorted(observed - expected)),
        )

    preserved = tuple(
        preserved_by_index[index] for index in range(first_identity.serial)
    )
    concatenation = b"".join(segment.derived_bytes for segment in preserved)
    return OpaqueSegmentSet(
        identity=first_identity,
        segments=preserved,
        derived_concatenation=concatenation,
        derived_concatenation_length=len(concatenation),
        derived_concatenation_sha256=sha256(concatenation).hexdigest(),
    )


def group_opaque_segment_sets(
    segments: list[OpaqueSegmentInput] | tuple[OpaqueSegmentInput, ...],
) -> tuple[OpaqueSegmentSet, ...]:
    """Partition by full envelope identity and assemble each complete set."""
    grouped: dict[OpaqueSegmentSetIdentity, list[OpaqueSegmentInput]] = {}
    for segment in segments:
        grouped.setdefault(_identity(segment), []).append(segment)
    return tuple(assemble_opaque_segment_set(group) for group in grouped.values())


def _identity(segment: OpaqueSegmentInput) -> OpaqueSegmentSetIdentity:
    _validate_batid(segment.batid)
    serial = normalize_segment_cardinality(
        "serial",
        segment.serial,
        allow_zero=False,
    )
    _validate_envelope_value("infoSize", segment.info_size)
    _validate_envelope_value("mid", segment.mid)
    _validate_envelope_value("type", segment.type)
    _validate_envelope_value("using", segment.using)
    return OpaqueSegmentSetIdentity(
        batid=segment.batid,
        serial=serial,
        info_size=segment.info_size,
        mid=segment.mid,
        type=segment.type,
        using=segment.using,
    )


def _preserve_segment(
    segment: OpaqueSegmentInput,
    *,
    index: int,
) -> PreservedOpaqueSegment:
    try:
        derived = decode_strict_base64_representation(segment.representation)
    except RepresentationDecodeError as err:
        message = f"Segment index {index} is not strict canonical Base64"
        raise InvalidSegmentRepresentationError(message) from err
    original = segment.representation.encode("ascii")
    return PreservedOpaqueSegment(
        index=index,
        original_representation=segment.representation,
        original_representation_length=len(original),
        original_representation_sha256=sha256(original).hexdigest(),
        derived_bytes=derived,
        derived_byte_length=len(derived),
        derived_sha256=sha256(derived).hexdigest(),
    )


def _validate_batid(value: str) -> None:
    if not isinstance(value, str) or not value:
        raise InvalidSegmentEnvelopeError("batid must be a non-empty string")


def normalize_segment_cardinality(
    name: str,
    value: SegmentCardinalityValue,
    *,
    allow_zero: bool,
) -> int:
    """Normalize only integers or canonical ASCII decimal strings."""
    if isinstance(value, bool):
        normalized: int | None = None
    elif isinstance(value, int):
        normalized = value
    elif (
        isinstance(value, str)
        and value
        and value.isascii()
        and value.isdigit()
        and (value == "0" or not value.startswith("0"))
    ):
        normalized = int(value)
    else:
        normalized = None
    if normalized is None or (normalized < 0 if allow_zero else normalized <= 0):
        expected = "non-negative" if allow_zero else "positive"
        message = (
            f"{name} must be a {expected} integer or canonical ASCII decimal string"
        )
        raise InvalidSegmentEnvelopeError(message)
    return normalized


def _validate_envelope_value(name: str, value: EnvelopeValue) -> None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        message = f"{name} must be an opaque string or integer"
        raise InvalidSegmentEnvelopeError(message)
