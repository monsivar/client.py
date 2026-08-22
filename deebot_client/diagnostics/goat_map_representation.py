"""Proven representation-layer handling for opaque GOAT map values."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from hashlib import sha256
import re

_STRICT_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


class RepresentationDecodeError(ValueError):
    """An opaque value does not satisfy the proven representation contract."""


@dataclass(frozen=True, slots=True)
class OnMiInfoRepresentation:
    """Original onMI.info text and its uninterpreted Base64-derived bytes."""

    original: str
    original_sha256: str
    decoded: bytes
    decoded_sha256: str
    encoding: str = "base64"


def decode_strict_base64_representation(original: str) -> bytes:
    """Strictly remove one canonical Base64 representation layer."""
    if not original:
        raise RepresentationDecodeError("Base64 representation must not be empty")
    try:
        original_bytes = original.encode("ascii")
    except UnicodeEncodeError as err:
        raise RepresentationDecodeError(
            "Base64 representation must contain ASCII only"
        ) from err
    if len(original_bytes) % 4 != 0:
        raise RepresentationDecodeError(
            "Base64 representation length must be divisible by four"
        )
    if _STRICT_BASE64_PATTERN.fullmatch(original) is None:
        raise RepresentationDecodeError(
            "Representation contains characters outside strict Base64"
        )
    try:
        decoded = base64.b64decode(original_bytes, validate=True)
    except binascii.Error as err:
        raise RepresentationDecodeError("Representation is not strict Base64") from err
    if base64.b64encode(decoded) != original_bytes:
        raise RepresentationDecodeError(
            "Representation is not canonical Base64 with exact round-trip"
        )
    return decoded


def decode_onmi_info_base64(original: str) -> bytes:
    """Strictly decode one onMI.info Base64 layer without interpreting bytes."""
    return decode_strict_base64_representation(original)


def preserve_onmi_info_representation(original: str) -> OnMiInfoRepresentation:
    """Preserve the original representation and digests around strict Base64."""
    original_bytes = original.encode("utf-8")
    decoded = decode_onmi_info_base64(original)
    return OnMiInfoRepresentation(
        original=original,
        original_sha256=sha256(original_bytes).hexdigest(),
        decoded=decoded,
        decoded_sha256=sha256(decoded).hexdigest(),
    )
