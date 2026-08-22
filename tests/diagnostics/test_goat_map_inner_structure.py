from __future__ import annotations

import base64
from datetime import UTC, datetime
from hashlib import sha256
from typing import TYPE_CHECKING

import orjson

from deebot_client.diagnostics.goat_map_capture import GoatMapCaptureWriter
from deebot_client.diagnostics.goat_map_inner_structure import (
    InnerStructureSample,
    analyze_inner_structure_corpus,
    analyze_inner_structure_samples,
)
from deebot_client.diagnostics.goat_map_refresh import MowerState

if TYPE_CHECKING:
    from pathlib import Path

_PREFIX = bytes.fromhex("5d00000400")
_INVARIANT = bytes.fromhex("002d96c042005e")


def _derived(
    *,
    family: str,
    info_size: int,
    offset_17: int,
    total_length: int,
    seed: int,
    embed_integer_candidates: bool = False,
) -> bytes:
    family_byte = 0x11 if family == "onMI" else 0x14
    value = bytearray(
        _PREFIX
        + info_size.to_bytes(4, "little")
        + _INVARIANT
        + bytes([family_byte, offset_17])
    )
    value.extend(
        (index * 37 + seed) % 256 for index in range(total_length - len(value))
    )
    if embed_integer_candidates:
        value[18:22] = info_size.to_bytes(4, "little")
        value[22:26] = total_length.to_bytes(4, "little")
    return bytes(value)


def _sample(
    *,
    capture: str,
    phase: str,
    family: str,
    association: str,
    serial: int | None,
    info_size: int,
    offset_17: int,
    total_length: int,
    control_transport: str | None = None,
    seed: int = 1,
    embed_integer_candidates: bool = False,
) -> InnerStructureSample:
    derived = _derived(
        family=family,
        info_size=info_size,
        offset_17=offset_17,
        total_length=total_length,
        seed=seed,
        embed_integer_candidates=embed_integer_candidates,
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
        control_transports=((control_transport,) if control_transport else ()),
        derived_bytes=derived,
        derived_sha256=sha256(derived).hexdigest(),
    )


def _relationship_samples() -> tuple[InnerStructureSample, ...]:
    samples: list[InnerStructureSample] = []
    specifications = (
        ("onMI", "cadence-associated", None, 25, 0xD8, 80),
        ("onMI", "request-associated", None, 1756, 0xD8, 90),
        ("onArI", "cadence-associated", 1, 1303, 0x63, 100),
        ("onArI", "request-associated", 2, 6316, 0xB4, 110),
    )
    for group_index, specification in enumerate(specifications):
        family, association, serial, info_size, offset_17, total_length = specification
        for independent_index in range(2):
            number = group_index * 2 + independent_index + 1
            samples.append(
                _sample(
                    capture=f"{number:x}" * 32,
                    phase=f"capture-{number}",
                    family=family,
                    association=association,
                    serial=serial,
                    info_size=info_size,
                    offset_17=offset_17,
                    total_length=total_length + independent_index,
                    seed=number,
                )
            )
    return tuple(samples)


def _file_digests(artifact_dir: Path) -> dict[str, str]:
    return {
        path.relative_to(artifact_dir).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in artifact_dir.rglob("*")
        if path.is_file()
    }


def test_inner_structure_analysis_is_deterministic_and_metadata_only() -> None:
    samples = _relationship_samples()

    first = analyze_inner_structure_samples(samples)
    second = analyze_inner_structure_samples(tuple(reversed(samples)))

    assert first == second
    assert first["structural_header_view_extended"] is False
    assert first["parser_implemented"] is False
    assert first["decoder_implemented"] is False
    serialized = orjson.dumps(first)
    for sample in samples:
        assert sample.derived_bytes not in serialized
        assert sample.derived_bytes.hex().encode() not in serialized


def test_offset_17_reports_raw_values_and_supported_joint_context() -> None:
    report = analyze_inner_structure_samples(_relationship_samples())

    assessment = report["offset_17_assessment"]
    assert assessment["column"]["stability"] == "variable"
    assert {
        (item["hex"], item["sample_count"], item["capture_count"])
        for item in assessment["column"]["values"]
    } == {("63", 2, 2), ("b4", 2, 2), ("d8", 4, 4)}
    joint = assessment["candidate_relations"]["message_family_plus_association"]
    assert joint["status"] == "supported"
    assert joint["counterexamples"] == []
    assert assessment["api_extension_recommended"] is False
    next_structure = report["next_evidence_based_structure"]
    assert next_structure["status"] == "supported"
    assert next_structure["offset"] == 17
    assert next_structure["width"] >= 1
    assert next_structure["internal_field_boundaries"] is None
    assert next_structure["structural_header_api_extension_recommended"] is False


def test_offset_17_serial_is_supported_but_family_and_association_are_rejected() -> (
    None
):
    report = analyze_inner_structure_samples(_relationship_samples())
    candidates = report["offset_17_assessment"]["candidate_relations"]

    assert candidates["onArI_serial"]["status"] == "supported"
    assert candidates["onArI_serial"]["values_by_context"] == [
        {
            "context": 1,
            "value": 0x63,
            "hex": "63",
            "sample_count": 2,
            "capture_count": 2,
        },
        {
            "context": 2,
            "value": 0xB4,
            "hex": "b4",
            "sample_count": 2,
            "capture_count": 2,
        },
    ]
    assert candidates["message_family"]["status"] == "rejected"
    assert candidates["message_family"]["counterexamples"]
    assert candidates["association"]["status"] == "rejected"
    assert candidates["association"]["counterexamples"]


def test_integer_candidate_detection_checks_info_size_and_total_length() -> None:
    samples = tuple(
        _sample(
            capture=str(index) * 32,
            phase=f"integer-{index}",
            family="onMI",
            association="request-associated",
            serial=None,
            info_size=1000 + index,
            offset_17=0xD8,
            total_length=100 + index,
            seed=index,
            embed_integer_candidates=True,
        )
        for index in (1, 2)
    )

    report = analyze_inner_structure_samples(samples)

    info_size = report["candidate_relations"]["infoSize"]
    assert info_size["status"] == "supported"
    assert any(
        item["offset"] == 18
        and item["width"] == 4
        and item["byte_order"] == "little"
        and item["status"] == "supported"
        for item in info_size["fields"]
    )
    total_length = report["candidate_relations"]["derived_total_length"]
    assert total_length["status"] == "supported"
    assert any(
        item["offset"] == 22
        and item["width"] == 4
        and item["byte_order"] == "little"
        and item["status"] == "supported"
        for item in total_length["fields"]
    )


def test_transport_is_reported_only_as_same_capture_control_context() -> None:
    legacy = _sample(
        capture="a" * 32,
        phase="paired",
        family="onArI",
        association="request-associated",
        serial=2,
        info_size=6316,
        offset_17=0xB4,
        total_length=100,
        control_transport="legacy",
        seed=1,
    )
    ngiot = _sample(
        capture="a" * 32,
        phase="paired",
        family="onArI",
        association="request-associated",
        serial=2,
        info_size=6316,
        offset_17=0xB4,
        total_length=110,
        control_transport="ngiot",
        seed=2,
    )

    report = analyze_inner_structure_samples((legacy, ngiot))

    controls = report["legacy_ngiot_control_comparisons"]
    assert controls["interpretation"] == "control-only-no-causal-attribution"
    assert controls["comparison_count"] == 1
    assert controls["identical_derived_count"] == 0
    assert controls["different_derived_count"] == 1
    assert controls["comparisons"][0]["left_length"] == 100
    assert controls["comparisons"][0]["right_length"] == 110
    assert controls["comparisons"][0]["first_differing_offset_at_or_after_17"] == 18
    variation = report["same_capture_same_role_length_variation"]
    assert len(variation) == 1
    assert variation[0]["distinct_length_count"] == 2


def test_candidate_output_has_no_semantic_content_names() -> None:
    report = analyze_inner_structure_samples(_relationship_samples())
    serialized = orjson.dumps(report["candidate_relations"]).lower()
    for forbidden in (b"polygon", b"coordinate", b"geometry", b"protobuf"):
        assert forbidden not in serialized


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
    derived = _derived(
        family="onMI",
        info_size=25,
        offset_17=0xD8,
        total_length=38,
        seed=1,
    )
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

    report = analyze_inner_structure_corpus((artifact,))

    assert report["corpus"]["sample_count"] == 1
    assert report["corpus"]["excluded_sample_count"] == 0
    assert _file_digests(artifact) == before
