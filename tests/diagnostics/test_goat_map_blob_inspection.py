from __future__ import annotations

from hashlib import sha256
from typing import TYPE_CHECKING

import orjson

from deebot_client.diagnostics.goat_map_blob_inspection import (
    inspect_onmi_info_artifact,
    inspect_opaque_bytes,
)
from deebot_client.diagnostics.goat_map_capture import GoatMapCaptureWriter
from deebot_client.diagnostics.goat_map_refresh import MowerState

if TYPE_CHECKING:
    from pathlib import Path


def _writer(artifact_dir: Path) -> GoatMapCaptureWriter:
    return GoatMapCaptureWriter(
        artifact_dir,
        phase="blob-inspection",
        mower_state=MowerState.MOWING,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq", "jmq": "none", "appping": "none"},
    )


def test_inspection_reports_52_and_876_byte_structure_without_map_decoding(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "capture"
    writer = _writer(artifact_dir)
    for info in ("A" * 876, "A" * 52, "A" * 876):
        writer.record_mqtt(
            "iot/atr/onMI/device/class/resource/j",
            orjson.dumps({"body": {"data": {"mid": "1", "info": info}}}),
        )
    writer.finalize()

    report = inspect_onmi_info_artifact(artifact_dir)

    assert report["representation_layer_decoding"] == "strict-syntax-candidates-only"
    assert report["semantic_map_decoding"] is False
    assert report["unique_blob_count"] == 2
    assert [blob["byte_length"] for blob in report["blobs"]] == [52, 876]
    assert [blob["observation_count"] for blob in report["blobs"]] == [1, 2]
    comparison = report["structural_comparisons"][0]
    assert comparison["length_delta_second_minus_first"] == 824
    assert comparison["common_prefix_bytes"] == 52
    assert comparison["common_suffix_bytes"] == 0
    assert comparison["first_differing_offset"] == 52
    base64_comparison = comparison["strict_text_layer_comparisons"][0]
    assert base64_comparison["encoding"] == "base64"
    assert base64_comparison["length_delta_second_minus_first"] == 618


def test_inspection_proves_only_strict_text_layer_and_magic_signature() -> None:
    result = inspect_opaque_bytes(b"1f8b080000000000")

    assert result["ascii_only"] is True
    assert result["ascii_printable_fraction"] == 1.0
    assert result["hex_character_fraction"] == 1.0
    assert result["compression_signatures"] == []
    candidates = {
        candidate["encoding"]: candidate
        for candidate in result["strict_text_encoding_candidates"]
    }
    assert set(candidates) == {"base64", "hex"}
    assert candidates["hex"] == {
        "encoding": "hex",
        "status": "strict-syntax-and-exact-round-trip",
        "decoded_byte_length": 8,
        "decoded_sha256": sha256(bytes.fromhex("1f8b080000000000")).hexdigest(),
        "decoded_leading_bytes_hex": "1f8b080000000000",
        "decoded_compression_signatures": ["gzip"],
    }
