from __future__ import annotations

import base64
from hashlib import sha256
from pathlib import Path

import orjson
import pytest

from deebot_client.diagnostics.goat_map_representation import (
    RepresentationDecodeError,
    decode_onmi_info_base64,
    preserve_onmi_info_representation,
)

_GOLDEN_FIXTURE = (
    Path(__file__).parents[1]
    / "fixtures"
    / "goat_map"
    / "onmi_info_representations.json"
)


@pytest.mark.parametrize(
    ("decoded_length", "representation_length"),
    [(38, 52), (657, 876)],
)
def test_repository_safe_golden_representation_round_trip(
    decoded_length: int,
    representation_length: int,
) -> None:
    decoded = bytes((index * 73 + 19) % 256 for index in range(decoded_length))
    original = base64.b64encode(decoded).decode("ascii")

    preserved = preserve_onmi_info_representation(original)

    assert len(original) == representation_length
    assert preserved.original == original
    assert preserved.original_sha256 == sha256(original.encode()).hexdigest()
    assert preserved.decoded == decoded
    assert preserved.decoded_sha256 == sha256(decoded).hexdigest()
    assert preserved.encoding == "base64"
    assert decode_onmi_info_base64(original) == decoded


def test_captured_golden_representations_are_byte_stable() -> None:
    fixtures = orjson.loads(_GOLDEN_FIXTURE.read_bytes())

    assert [fixture["label"] for fixture in fixtures] == [
        "periodic-52",
        "immediate-876",
    ]
    assert [fixture["info_size"] for fixture in fixtures] == [25, 1756]
    for fixture in fixtures:
        preserved = preserve_onmi_info_representation(fixture["original"])
        assert len(preserved.original.encode()) == fixture["original_byte_length"]
        assert preserved.original_sha256 == fixture["original_sha256"]
        assert len(preserved.decoded) == fixture["decoded_byte_length"]
        assert preserved.decoded_sha256 == fixture["decoded_sha256"]


@pytest.mark.parametrize(
    "invalid",
    [
        "",
        "AAA",
        "AAAA\n",
        "AA-A",
        "A===",
        "AB==",
        "æAAA",
    ],
)
def test_strict_base64_rejects_invalid_or_noncanonical_input(invalid: str) -> None:
    with pytest.raises(RepresentationDecodeError):
        decode_onmi_info_base64(invalid)
