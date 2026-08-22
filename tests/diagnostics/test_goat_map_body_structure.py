from __future__ import annotations

import base64
from datetime import UTC, datetime
from hashlib import sha256
from typing import TYPE_CHECKING

import orjson

from deebot_client.diagnostics.goat_map_body_structure import (
    BodyStructureSample,
    analyze_body_structure_corpus,
    analyze_body_structure_samples,
    collect_body_structure_samples,
)
from deebot_client.diagnostics.goat_map_capture import GoatMapCaptureWriter
from deebot_client.diagnostics.goat_map_inner_structure import InnerStructureSample
from deebot_client.diagnostics.goat_map_refresh import MowerState

if TYPE_CHECKING:
    from pathlib import Path

_PREFIX = bytes.fromhex("5d00000400")
_INVARIANT = bytes.fromhex("002d96c042005e")
_ONMI_SHORT_SIGNATURE = bytes.fromhex("d87941b0124e4b661976770c2fe196de4f")
_ONMI_LONG_SIGNATURE = bytes.fromhex("d87941b05cc7ff714f1e78d8dc93bd81d1")
_ONARI_SERIAL_1_SIGNATURE = bytes.fromhex("63d1dceaf6490fc728b85a4e13e18bae5c")


def _source_sample(
    *,
    capture: str,
    phase: str,
    signature: bytes,
    remainder: bytes,
    info_size: int,
    family: str,
    association: str,
    serial: int | None,
) -> InnerStructureSample:
    family_byte = 0x11 if family == "onMI" else 0x14
    derived = (
        _PREFIX
        + info_size.to_bytes(4, "little")
        + _INVARIANT
        + bytes([family_byte])
        + signature
        + remainder
    )
    return InnerStructureSample(
        capture_id=capture,
        phase=phase,
        timestamp="2026-08-22T12:00:00+00:00",
        windows=(f"{phase}:window",),
        message_family="onMI" if family == "onMI" else "onArI",
        association=(
            "request-associated"
            if association == "request-associated"
            else "cadence-associated"
        ),
        serial=serial,
        info_size=info_size,
        event_transports=("normal-mq",),
        control_transports=(),
        derived_bytes=derived,
        derived_sha256=sha256(derived).hexdigest(),
    )


def _body_sample(**kwargs: object) -> BodyStructureSample:
    source = _source_sample(**kwargs)  # type: ignore[arg-type]
    collected, exclusions = collect_body_structure_samples((source,))
    assert exclusions == []
    assert len(collected) == 1
    return collected[0]


def _file_digests(artifact_dir: Path) -> dict[str, str]:
    return {
        path.relative_to(artifact_dir).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in artifact_dir.rglob("*")
        if path.is_file()
    }


def test_exact_signatures_are_never_merged_despite_shared_context_class() -> None:
    samples = (
        _body_sample(
            capture="1" * 32,
            phase="short",
            signature=_ONMI_SHORT_SIGNATURE,
            remainder=b"same-context-class-a",
            info_size=25,
            family="onMI",
            association="cadence-associated",
            serial=None,
        ),
        _body_sample(
            capture="2" * 32,
            phase="long",
            signature=_ONMI_LONG_SIGNATURE,
            remainder=b"same-context-class-b",
            info_size=1756,
            family="onMI",
            association="request-associated",
            serial=None,
        ),
    )

    report = analyze_body_structure_samples(samples)

    assert report["grouping_key"] == "exact-context-signature-raw-bytes"
    assert report["corpus"]["exact_signature_count"] == 2
    groups = report["signature_groups"]
    assert {
        group["signature_identity"]["context_signature_hex"] for group in groups
    } == {
        _ONMI_SHORT_SIGNATURE.hex(),
        _ONMI_LONG_SIGNATURE.hex(),
    }
    assert all(
        group["signature_identity"]["observed_context_classes"] == ["observed-onMI"]
        for group in groups
    )


def test_priority_prefers_most_cross_capture_identical_remainders() -> None:
    samples = [
        _body_sample(
            capture=f"{index + 1:x}" * 32,
            phase=f"stable-{index}",
            signature=_ONMI_SHORT_SIGNATURE,
            remainder=b"byte-identical-body",
            info_size=25,
            family="onMI",
            association="cadence-associated",
            serial=None,
        )
        for index in range(4)
    ]
    samples.extend(
        [
            _body_sample(
                capture=f"{index + 8:x}" * 32,
                phase=f"variable-{index}",
                signature=_ONMI_LONG_SIGNATURE,
                remainder=f"different-{index}".encode(),
                info_size=1756,
                family="onMI",
                association="request-associated",
                serial=None,
            )
            for index in range(3)
        ]
    )

    report = analyze_body_structure_samples(samples)

    priority = report["priority_order"][0]
    assert priority["context_signature_hex"] == _ONMI_SHORT_SIGNATURE.hex()
    assert priority["reason"] == "cross-capture-byte-identical-remainders"
    assert priority["max_identical_cross_capture_sample_count"] == 4
    assert priority["max_identical_cross_capture_capture_count"] == 4


def test_common_edges_and_first_difference_are_reported_with_offsets() -> None:
    samples = tuple(
        _body_sample(
            capture=str(index) * 32,
            phase=f"edges-{index}",
            signature=_ONARI_SERIAL_1_SIGNATURE,
            remainder=b"prefix-" + bytes([index]) + b"-suffix",
            info_size=1300 + index,
            family="onArI",
            association="cadence-associated",
            serial=1,
        )
        for index in (1, 2)
    )

    group = analyze_body_structure_samples(samples)["signature_groups"][0]
    common = group["common_structure"]

    assert common["common_prefix_length"] == len(b"prefix-")
    assert common["common_suffix_length"] == len(b"-suffix")
    assert common["first_differing_remainder_offset"] == len(b"prefix-")
    assert common["first_differing_absolute_offset"] == 34 + len(b"prefix-")
    candidates = group["structural_candidates"]
    assert candidates["stable_common_prefix_boundary"]["status"] == "supported"
    assert candidates["stable_common_suffix"]["status"] == "supported"


def test_identical_remainder_is_supported_without_inventing_a_boundary() -> None:
    samples = tuple(
        _body_sample(
            capture=str(index) * 32,
            phase=f"stable-{index}",
            signature=_ONMI_SHORT_SIGNATURE,
            remainder=b"byte-identical",
            info_size=25,
            family="onMI",
            association="cadence-associated",
            serial=None,
        )
        for index in (1, 2)
    )

    candidates = analyze_body_structure_samples(samples)["signature_groups"][0][
        "structural_candidates"
    ]

    assert candidates["exact_remainder_repeatability"]["status"] == "supported"
    boundary = candidates["stable_common_prefix_boundary"]
    assert boundary["status"] == "rejected"
    assert boundary["first_differing_absolute_offset"] is None


def test_integer_candidates_detect_known_synthetic_relations() -> None:
    samples: list[BodyStructureSample] = []
    for index in (1, 2):
        info_size = 1000 + index
        remainder_length = 100 + index
        derived_length = 34 + remainder_length
        remainder = bytearray(remainder_length)
        remainder[0:4] = info_size.to_bytes(4, "little")
        remainder[4:8] = derived_length.to_bytes(4, "little")
        remainder[8:12] = remainder_length.to_bytes(4, "little")
        samples.append(
            _body_sample(
                capture=str(index) * 32,
                phase=f"integer-{index}",
                signature=_ONARI_SERIAL_1_SIGNATURE,
                remainder=bytes(remainder),
                info_size=info_size,
                family="onArI",
                association="cadence-associated",
                serial=1,
            )
        )

    relations = analyze_body_structure_samples(samples)["signature_groups"][0][
        "candidate_relations"
    ]

    assert _has_supported_field(relations["infoSize"], 0, 4)
    assert _has_supported_field(relations["derived_total_length"], 4, 4)
    assert _has_supported_field(relations["remainder_length"], 8, 4)
    assert relations["assembled_index"]["status"] == "rejected"


def test_repeating_structure_candidate_requires_cross_capture_support() -> None:
    repeated = b"ABCD" * 3 + b"opaque"
    samples = tuple(
        _body_sample(
            capture=str(index) * 32,
            phase=f"repeat-{index}",
            signature=_ONARI_SERIAL_1_SIGNATURE,
            remainder=repeated,
            info_size=1300 + index,
            family="onArI",
            association="cadence-associated",
            serial=1,
        )
        for index in (1, 2)
    )

    repetition = analyze_body_structure_samples(samples)["signature_groups"][0][
        "repeating_structure_candidates"
    ]

    candidate = next(
        item
        for item in repetition["candidates"]
        if item["remainder_offset"] == 0 and item["block_width"] == 4
    )
    assert candidate["repeat_count"] == 3
    assert candidate["status"] == "supported"
    assert candidate["counterexamples"] == []


def test_same_and_cross_capture_repeatability_are_separate() -> None:
    samples = (
        _body_sample(
            capture="a" * 32,
            phase="same-a",
            signature=_ONMI_SHORT_SIGNATURE,
            remainder=b"identical",
            info_size=25,
            family="onMI",
            association="cadence-associated",
            serial=None,
        ),
        _body_sample(
            capture="a" * 32,
            phase="same-b",
            signature=_ONMI_SHORT_SIGNATURE,
            remainder=b"identical",
            info_size=25,
            family="onMI",
            association="cadence-associated",
            serial=None,
        ),
        _body_sample(
            capture="b" * 32,
            phase="cross",
            signature=_ONMI_SHORT_SIGNATURE,
            remainder=b"identical",
            info_size=25,
            family="onMI",
            association="cadence-associated",
            serial=None,
        ),
    )

    group = analyze_body_structure_samples(samples)["signature_groups"][0]

    assert group["same_capture_repeatability"]["pair_count"] == 1
    assert group["same_capture_repeatability"]["identical_pair_count"] == 1
    assert group["cross_capture_repeatability"]["pair_count"] == 2
    assert group["cross_capture_repeatability"]["identical_pair_count"] == 2


def test_report_is_deterministic_metadata_only_and_has_no_semantic_guesses() -> None:
    samples = tuple(
        _body_sample(
            capture=str(index) * 32,
            phase=f"metadata-{index}",
            signature=_ONARI_SERIAL_1_SIGNATURE,
            remainder=b"opaque-body-" + bytes([index]),
            info_size=1300 + index,
            family="onArI",
            association="cadence-associated",
            serial=1,
        )
        for index in (1, 2)
    )

    first = analyze_body_structure_samples(samples)
    second = analyze_body_structure_samples(tuple(reversed(samples)))

    assert first == second
    serialized = orjson.dumps(first)
    for sample in samples:
        assert sample.remainder not in serialized
        assert sample.remainder.hex().encode() not in serialized
    lowered = serialized.lower()
    for forbidden in (b"coordinate", b"geometry", b"protobuf", b"float"):
        assert forbidden not in lowered


def test_artifact_corpus_analysis_is_read_only(tmp_path: Path) -> None:
    artifact = tmp_path / "capture-a"
    writer = GoatMapCaptureWriter(
        artifact,
        phase="capture-a",
        mower_state=MowerState.MOWING,
        device_class="fixture-class",
        factors={"mqtt": "normal-mq"},
        capture_id_factory=lambda: "a" * 32,
    )
    remainder = b"body"
    derived = (
        _PREFIX
        + (25).to_bytes(4, "little")
        + _INVARIANT
        + b"\x11"
        + _ONMI_SHORT_SIGNATURE
        + remainder
    )
    assert len(base64.b64encode(derived)) == 52
    writer.record_mqtt(
        "iot/atr/onMI/device/class/resource/j",
        orjson.dumps(
            {
                "body": {
                    "data": {
                        "mid": "1",
                        "info": base64.b64encode(derived).decode(),
                        "infoSize": 25,
                    }
                }
            }
        ),
        observed_at=datetime(2026, 8, 22, 12, tzinfo=UTC),
    )
    writer.finalize()
    before = _file_digests(artifact)

    report = analyze_body_structure_corpus((artifact,))

    assert report["corpus"]["sample_count"] == 1
    assert report["corpus"]["exact_signature_count"] == 1
    assert _file_digests(artifact) == before


def _has_supported_field(
    relation: dict[str, object],
    offset: int,
    width: int,
) -> bool:
    fields = relation["fields"]
    assert isinstance(fields, list)
    return any(
        item["remainder_offset"] == offset
        and item["width"] == width
        and item["byte_order"] == "little"
        and item["status"] == "supported"
        for item in fields
    )
