"""Read-only representation analysis for opaque GOAT map capture blobs."""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
from itertools import combinations
import math
import re
from typing import TYPE_CHECKING, Any

import orjson

from .goat_map_representation import (
    RepresentationDecodeError,
    decode_onmi_info_base64,
)

if TYPE_CHECKING:
    from pathlib import Path

_ON_MI_INFO_PATH = "$.body.data.info"
_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAGIC_PREFIXES = (
    ("gzip", b"\x1f\x8b"),
    ("bzip2", b"BZh"),
    ("xz", b"\xfd7zXZ\x00"),
    ("zip", b"PK\x03\x04"),
    ("zstandard", b"\x28\xb5\x2f\xfd"),
    ("lz4-frame", b"\x04\x22\x4d\x18"),
)


class BlobInspectionError(ValueError):
    """An artifact cannot be inspected without violating its schema."""


def inspect_onmi_info_artifact(artifact_dir: Path) -> dict[str, Any]:
    """Inspect unique onMI.info originals without modifying or decoding the map."""
    manifest = _load_json_object(artifact_dir / "manifest.json")
    records_path = artifact_dir / str(manifest.get("records_file", "records.jsonl"))
    unique: dict[str, bytes] = {}
    observations: Counter[str] = Counter()
    for line in records_path.read_bytes().splitlines():
        record = orjson.loads(line)
        if not isinstance(record, dict) or record.get("command") != "onMI":
            continue
        for segment in record.get("opaque_segments", []):
            if (
                not isinstance(segment, dict)
                or segment.get("source_path") != _ON_MI_INFO_PATH
            ):
                continue
            original = segment.get("representations", {}).get("original")
            if not isinstance(original, dict):
                raise BlobInspectionError(
                    "onMI.info segment has no original representation"
                )
            digest = str(original.get("sha256", ""))
            if not _DIGEST_PATTERN.fullmatch(digest):
                raise BlobInspectionError("onMI.info segment has an invalid SHA-256")
            expected_blob = f"blobs/{digest}.bin"
            if original.get("blob") != expected_blob:
                raise BlobInspectionError("Blob reference is not content-addressed")
            raw = (artifact_dir / "blobs" / f"{digest}.bin").read_bytes()
            if sha256(raw).hexdigest() != digest:
                raise BlobInspectionError("Blob digest verification failed")
            if original.get("byte_length") != len(raw):
                raise BlobInspectionError("Blob byte length verification failed")
            unique[digest] = raw
            observations[digest] += 1

    ordered = sorted(unique.items(), key=lambda item: (len(item[1]), item[0]))
    return {
        "analysis_kind": "opaque-representation-inspection/v1",
        "representation_layer_decoding": "strict-syntax-candidates-only",
        "semantic_map_decoding": False,
        "source_path": _ON_MI_INFO_PATH,
        "capture_id": manifest.get("capture_id"),
        "unique_blob_count": len(ordered),
        "blobs": [
            {
                **inspect_opaque_bytes(raw),
                "observation_count": observations[digest],
            }
            for digest, raw in ordered
        ],
        "structural_comparisons": [
            _compare_blobs(first_digest, first, second_digest, second)
            for (first_digest, first), (second_digest, second) in combinations(
                ordered, 2
            )
        ],
        "interpretation_guard": (
            "Encoding matches are syntax-only representation observations; "
            "no result is a decoded map."
        ),
    }


def inspect_opaque_bytes(raw: bytes) -> dict[str, Any]:
    """Return non-semantic byte and text properties for one opaque value."""
    byte_count = len(raw)
    ascii_printable = sum(byte in {9, 10, 13} or 32 <= byte <= 126 for byte in raw)
    ascii_only = all(byte < 128 for byte in raw)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None

    hex_chars = sum(chr(byte) in "0123456789abcdefABCDEF" for byte in raw)
    base64_chars = sum(
        chr(byte) in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        for byte in raw
    )
    candidates = [
        _derived_layer(name, decoded)
        for name, decoded in _strict_text_layers(raw).items()
    ]

    return {
        "sha256": sha256(raw).hexdigest(),
        "byte_length": byte_count,
        "unique_byte_count": len(set(raw)),
        "shannon_entropy_bits_per_byte": _entropy(raw),
        "ascii_only": ascii_only,
        "utf8_valid": text is not None,
        "ascii_printable_fraction": ascii_printable / byte_count if byte_count else 1.0,
        "hex_character_fraction": hex_chars / byte_count if byte_count else 0.0,
        "base64_character_fraction": base64_chars / byte_count if byte_count else 0.0,
        "leading_bytes_hex": raw[:8].hex(),
        "compression_signatures": _compression_signatures(raw),
        "strict_text_encoding_candidates": candidates,
    }


def _derived_layer(name: str, decoded: bytes) -> dict[str, Any]:
    return {
        "encoding": name,
        "status": "strict-syntax-and-exact-round-trip",
        "decoded_byte_length": len(decoded),
        "decoded_sha256": sha256(decoded).hexdigest(),
        "decoded_leading_bytes_hex": decoded[:8].hex(),
        "decoded_compression_signatures": _compression_signatures(decoded),
    }


def _strict_text_layers(raw: bytes) -> dict[str, bytes]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {}
    layers: dict[str, bytes] = {}
    if text and len(text) % 2 == 0 and _HEX_PATTERN.fullmatch(text):
        decoded = bytes.fromhex(text)
        if decoded.hex().casefold() == text.casefold():
            layers["hex"] = decoded
    if text:
        try:
            decoded = decode_onmi_info_base64(text)
        except RepresentationDecodeError:
            pass
        else:
            layers["base64"] = decoded
    return layers


def _compression_signatures(raw: bytes) -> list[str]:
    matches = [name for name, prefix in _MAGIC_PREFIXES if raw.startswith(prefix)]
    if len(raw) >= 2 and raw[0] & 0x0F == 8 and (raw[0] << 8 | raw[1]) % 31 == 0:
        matches.append("zlib")
    return matches


def _entropy(raw: bytes) -> float:
    if not raw:
        return 0.0
    length = len(raw)
    return -sum(
        (count / length) * math.log2(count / length) for count in Counter(raw).values()
    )


def _compare_blobs(
    first_digest: str,
    first: bytes,
    second_digest: str,
    second: bytes,
) -> dict[str, Any]:
    structure = _byte_structure(first, second)
    first_layers = _strict_text_layers(first)
    second_layers = _strict_text_layers(second)
    common_layers = sorted(first_layers.keys() & second_layers.keys())
    return {
        "first_sha256": first_digest,
        "first_byte_length": len(first),
        "second_sha256": second_digest,
        "second_byte_length": len(second),
        **structure,
        "strict_text_layer_comparisons": [
            {
                "encoding": encoding,
                "first_decoded_sha256": sha256(first_layers[encoding]).hexdigest(),
                "second_decoded_sha256": sha256(second_layers[encoding]).hexdigest(),
                **_byte_structure(
                    first_layers[encoding],
                    second_layers[encoding],
                ),
            }
            for encoding in common_layers
        ],
    }


def _byte_structure(first: bytes, second: bytes) -> dict[str, Any]:
    shared_prefix = 0
    for left, right in zip(first, second, strict=False):
        if left != right:
            break
        shared_prefix += 1
    shared_suffix = 0
    remaining = min(len(first), len(second)) - shared_prefix
    while (
        shared_suffix < remaining
        and first[-shared_suffix - 1] == second[-shared_suffix - 1]
    ):
        shared_suffix += 1
    return {
        "length_delta_second_minus_first": len(second) - len(first),
        "common_prefix_bytes": shared_prefix,
        "common_suffix_bytes": shared_suffix,
        "first_differing_offset": shared_prefix if first != second else None,
    }


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        parsed = orjson.loads(path.read_bytes())
    except (OSError, orjson.JSONDecodeError) as err:
        message = f"Cannot read capture metadata: {path.name}"
        raise BlobInspectionError(message) from err
    if not isinstance(parsed, dict):
        message = f"Capture metadata is not an object: {path.name}"
        raise BlobInspectionError(message)
    return parsed
