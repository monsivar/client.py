"""Minimal lossless view of the observed bytes at offsets 17..33."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from .goat_map_structural_header import StructuralHeaderView

type ObservedContextClass = Literal[
    "observed-onMI",
    "observed-onArI-63-signature",
    "observed-onArI-b4-signature",
    "unknown",
]

_CONTEXT_SIGNATURE_OFFSET = 17
_CONTEXT_SIGNATURE_LENGTH = 17
_REMAINDER_OFFSET = 34
_OBSERVED_ONMI_SIGNATURES = frozenset(
    {
        bytes.fromhex("d87941b0124e4b661976770c2fe196de4f"),
        bytes.fromhex("d87941b05cc7ff714f1e78d8dc93bd81d1"),
    }
)
_OBSERVED_ONARI_63_SIGNATURE = bytes.fromhex("63d1dceaf6490fc728b85a4e13e18bae5c")
_OBSERVED_ONARI_B4_SIGNATURE = bytes.fromhex("b4fc81d4375de7a0f636f001dc016fe0ca")


class InnerStructureViewError(ValueError):
    """Base error for an invalid inner structural view."""


class InnerStructureViewTooShortError(InnerStructureViewError):
    """The outer frame does not contain all bytes at offsets 17..33."""


class InnerStructureFamilyMismatchError(InnerStructureViewError):
    """A known context signature conflicts with the observed outer family."""


@dataclass(frozen=True, slots=True)
class InnerStructureView:
    """A byte-preserving classification view with an opaque remainder."""

    structural_header: StructuralHeaderView
    original_bytes: bytes
    context_signature_raw: bytes
    observed_context_class: ObservedContextClass
    envelope_serial: int | None
    remainder: bytes

    def to_bytes(self) -> bytes:
        """Return the original uninterpreted bytes byte-for-byte."""
        return self.original_bytes


def recognize_inner_structure(
    structural_header: StructuralHeaderView,
    *,
    envelope_serial: int | None = None,
) -> InnerStructureView:
    """Classify only byte-identical observed 17..33 signatures."""
    original = structural_header.original_bytes
    if len(original) < _REMAINDER_OFFSET:
        message = (
            "Inner structural view requires all bytes at offsets 17..33 "
            f"({_REMAINDER_OFFSET} bytes total)"
        )
        raise InnerStructureViewTooShortError(message)
    if envelope_serial is not None and (
        isinstance(envelope_serial, bool) or not isinstance(envelope_serial, int)
    ):
        raise TypeError("envelope_serial must be an integer or None")

    signature = original[
        _CONTEXT_SIGNATURE_OFFSET : _CONTEXT_SIGNATURE_OFFSET
        + _CONTEXT_SIGNATURE_LENGTH
    ]
    context_class, expected_family = _classify_signature(signature)
    if (
        expected_family is not None
        and structural_header.observed_family != expected_family
    ):
        message = (
            "Observed context signature conflicts with outer family: "
            f"signature_family={expected_family}, "
            f"outer_family={structural_header.observed_family}"
        )
        raise InnerStructureFamilyMismatchError(message)

    return InnerStructureView(
        structural_header=structural_header,
        original_bytes=original,
        context_signature_raw=signature,
        observed_context_class=context_class,
        envelope_serial=envelope_serial,
        remainder=original[_REMAINDER_OFFSET:],
    )


def _classify_signature(
    signature: bytes,
) -> tuple[ObservedContextClass, Literal["onMI", "onArI"] | None]:
    if signature in _OBSERVED_ONMI_SIGNATURES:
        return "observed-onMI", "onMI"
    if signature == _OBSERVED_ONARI_63_SIGNATURE:
        return "observed-onArI-63-signature", "onArI"
    if signature == _OBSERVED_ONARI_B4_SIGNATURE:
        return "observed-onArI-b4-signature", "onArI"
    return "unknown", None
