from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from scripts import goat_map_phase2_capture

if TYPE_CHECKING:
    from pathlib import Path


def test_controlled_area_split_cli_is_passive_and_validated(tmp_path: Path) -> None:
    args = goat_map_phase2_capture._parser().parse_args(
        [
            "--mode",
            "controlled-area-split",
            "--country",
            "NO",
            "--phase",
            "p2-09-controlled-area-split",
            "--mower-state",
            "paused",
            "--device-class",
            "2i0fns",
            "--baseline-seconds",
            "45",
            "--app-init-seconds",
            "45",
            "--between-init-quiet-seconds",
            "10",
            "--post-split-seconds",
            "150",
            "--post-split-reopen",
            "--post-reopen-seconds",
            "60",
            "--artifact-dir",
            str(tmp_path / "new-artifact"),
        ]
    )

    goat_map_phase2_capture._validate_args(args)

    assert args.mode == "controlled-area-split"
    assert args.mower_state == "paused"
    assert args.post_split_reopen is True


def test_controlled_area_split_cli_rejects_non_paused_state(tmp_path: Path) -> None:
    args = goat_map_phase2_capture._parser().parse_args(
        [
            "--mode",
            "controlled-area-split",
            "--country",
            "NO",
            "--mower-state",
            "mowing",
            "--device-class",
            "2i0fns",
            "--artifact-dir",
            str(tmp_path / "new-artifact"),
        ]
    )

    with pytest.raises(ValueError, match="paused"):
        goat_map_phase2_capture._validate_args(args)


def test_controlled_area_merge_cli_is_passive_and_uses_immutable_reference(
    tmp_path: Path,
) -> None:
    reference = tmp_path / "p2-09c-reference"
    args = goat_map_phase2_capture._parser().parse_args(
        [
            "--mode",
            "controlled-area-merge",
            "--country",
            "NO",
            "--phase",
            "p2-10-controlled-area-merge",
            "--mower-state",
            "paused",
            "--device-class",
            "2i0fns",
            "--baseline-seconds",
            "45",
            "--app-init-seconds",
            "45",
            "--between-init-quiet-seconds",
            "10",
            "--post-merge-seconds",
            "150",
            "--post-merge-reopen",
            "--post-merge-reopen-seconds",
            "60",
            "--restoration-reference-artifact",
            str(reference),
            "--artifact-dir",
            str(tmp_path / "new-merge-artifact"),
        ]
    )

    goat_map_phase2_capture._validate_args(args)

    assert args.mode == "controlled-area-merge"
    assert args.post_split_reopen is True
    assert args.post_split_seconds == 150
    assert args.restoration_reference_artifact == reference


def test_controlled_area_merge_recovery_cli_is_passive(tmp_path: Path) -> None:
    original = tmp_path / "p2-09c"
    pre_merge = tmp_path / "p2-10"
    args = goat_map_phase2_capture._parser().parse_args(
        [
            "--mode",
            "controlled-area-merge-recovery",
            "--country",
            "NO",
            "--phase",
            "p2-10c-controlled-area-merge-recovery",
            "--mower-state",
            "paused",
            "--device-class",
            "2i0fns",
            "--baseline-seconds",
            "45",
            "--app-init-seconds",
            "45",
            "--between-init-quiet-seconds",
            "10",
            "--restoration-reference-artifact",
            str(original),
            "--pre-merge-reference-artifact",
            str(pre_merge),
            "--artifact-dir",
            str(tmp_path / "recovery"),
        ]
    )

    goat_map_phase2_capture._validate_args(args)

    assert args.mode == "controlled-area-merge-recovery"
    assert args.restoration_reference_artifact == original
    assert args.pre_merge_reference_artifact == pre_merge


def test_controlled_area_rename_cli_is_passive_and_records_lengths(
    tmp_path: Path,
) -> None:
    c_state = tmp_path / "p2-10d"
    divide = tmp_path / "p2-09c"
    args = goat_map_phase2_capture._parser().parse_args(
        [
            "--mode",
            "controlled-area-rename",
            "--country",
            "NO",
            "--phase",
            "p2-11-controlled-area-rename",
            "--mower-state",
            "paused",
            "--device-class",
            "2i0fns",
            "--baseline-seconds",
            "45",
            "--app-init-seconds",
            "45",
            "--between-init-quiet-seconds",
            "10",
            "--post-rename-seconds",
            "150",
            "--post-rename-reopen",
            "--post-rename-reopen-seconds",
            "60",
            "--rename-reference-artifact",
            str(c_state),
            "--divide-write-reference-artifact",
            str(divide),
            "--old-name-utf8-byte-length",
            "5",
            "--new-name-utf8-byte-length",
            "5",
            "--artifact-dir",
            str(tmp_path / "new-rename-artifact"),
        ]
    )

    goat_map_phase2_capture._validate_args(args)

    assert args.mode == "controlled-area-rename"
    assert args.mower_state == "paused"
    assert args.post_split_seconds == 150
    assert args.post_split_reopen is True
    assert args.post_reopen_seconds == 60
    assert args.rename_reference_artifact == c_state
    assert args.divide_write_reference_artifact == divide
    assert args.old_name_utf8_byte_length == 5
    assert args.new_name_utf8_byte_length == 5


def test_controlled_area_rename_cli_requires_name_lengths(tmp_path: Path) -> None:
    args = goat_map_phase2_capture._parser().parse_args(
        [
            "--mode",
            "controlled-area-rename",
            "--country",
            "NO",
            "--phase",
            "p2-11-controlled-area-rename",
            "--mower-state",
            "paused",
            "--device-class",
            "2i0fns",
            "--post-rename-reopen",
            "--artifact-dir",
            str(tmp_path / "new-rename-artifact"),
        ]
    )

    with pytest.raises(ValueError, match="name lengths"):
        goat_map_phase2_capture._validate_args(args)


def test_controlled_area_rename_restore_cli_is_passive_and_fixed_length(
    tmp_path: Path,
) -> None:
    p2_11 = tmp_path / "p2-11"
    divide = tmp_path / "p2-09c"
    args = goat_map_phase2_capture._parser().parse_args(
        [
            "--mode",
            "controlled-area-rename-restore",
            "--country",
            "NO",
            "--phase",
            "p2-12-controlled-area-rename-restore",
            "--mower-state",
            "paused",
            "--device-class",
            "2i0fns",
            "--baseline-seconds",
            "45",
            "--app-init-seconds",
            "45",
            "--between-init-quiet-seconds",
            "10",
            "--post-restore-seconds",
            "150",
            "--post-restore-reopen",
            "--post-restore-reopen-seconds",
            "60",
            "--old-name-utf8-byte-length",
            "5",
            "--new-name-utf8-byte-length",
            "5",
            "--rename-restore-reference-artifact",
            str(p2_11),
            "--divide-write-reference-artifact",
            str(divide),
            "--artifact-dir",
            str(tmp_path / "p2-12"),
        ]
    )

    goat_map_phase2_capture._validate_args(args)

    assert args.mode == "controlled-area-rename-restore"
    assert args.mower_state == "paused"
    assert args.post_split_seconds == 150
    assert args.post_split_reopen is True
    assert args.post_reopen_seconds == 60
    assert args.rename_restore_reference_artifact == p2_11
    assert args.divide_write_reference_artifact == divide
    assert args.old_name_utf8_byte_length == 5
    assert args.new_name_utf8_byte_length == 5


def test_controlled_area_noop_save_cli_uses_p2_12c_reference(
    tmp_path: Path,
) -> None:
    p2_12c = tmp_path / "p2-12c"
    args = goat_map_phase2_capture._parser().parse_args(
        [
            "--mode",
            "controlled-area-noop-save",
            "--country",
            "NO",
            "--phase",
            "p2-13-controlled-area-noop-save",
            "--mower-state",
            "paused",
            "--device-class",
            "2i0fns",
            "--baseline-seconds",
            "45",
            "--app-init-seconds",
            "45",
            "--between-init-quiet-seconds",
            "10",
            "--post-noop-save-seconds",
            "150",
            "--post-noop-save-reopen",
            "--post-noop-save-reopen-seconds",
            "60",
            "--noop-save-reference-artifact",
            str(p2_12c),
            "--artifact-dir",
            str(tmp_path / "p2-13"),
        ]
    )

    goat_map_phase2_capture._validate_args(args)

    assert args.mode == "controlled-area-noop-save"
    assert args.post_split_seconds == 150
    assert args.post_split_reopen is True
    assert args.post_reopen_seconds == 60
    assert args.noop_save_reference_artifact == p2_12c


def test_controlled_area_same_name_cli_is_separate_and_fixed_length(
    tmp_path: Path,
) -> None:
    p2_12c = tmp_path / "p2-12c"
    p2_11 = tmp_path / "p2-11"
    args = goat_map_phase2_capture._parser().parse_args(
        [
            "--mode",
            "controlled-area-same-name-resubmission",
            "--country",
            "NO",
            "--phase",
            "p2-13b-controlled-area-same-name-resubmission",
            "--mower-state",
            "paused",
            "--device-class",
            "2i0fns",
            "--baseline-seconds",
            "45",
            "--app-init-seconds",
            "45",
            "--between-init-quiet-seconds",
            "10",
            "--post-same-name-seconds",
            "150",
            "--post-same-name-reopen",
            "--post-same-name-reopen-seconds",
            "60",
            "--old-name-utf8-byte-length",
            "5",
            "--new-name-utf8-byte-length",
            "5",
            "--same-name-reference-artifact",
            str(p2_12c),
            "--same-name-write-reference-artifact",
            str(p2_11),
            "--artifact-dir",
            str(tmp_path / "p2-13b"),
        ]
    )

    goat_map_phase2_capture._validate_args(args)

    assert args.mode == "controlled-area-same-name-resubmission"
    assert args.post_split_seconds == 150
    assert args.post_split_reopen is True
    assert args.old_name_utf8_byte_length == 5
    assert args.new_name_utf8_byte_length == 5
    assert args.same_name_reference_artifact == p2_12c
    assert args.same_name_write_reference_artifact == p2_11


def test_controlled_area_rename_restore_cli_rejects_length_change(
    tmp_path: Path,
) -> None:
    args = goat_map_phase2_capture._parser().parse_args(
        [
            "--mode",
            "controlled-area-rename-restore",
            "--country",
            "NO",
            "--phase",
            "p2-12-controlled-area-rename-restore",
            "--mower-state",
            "paused",
            "--device-class",
            "2i0fns",
            "--post-restore-reopen",
            "--old-name-utf8-byte-length",
            "5",
            "--new-name-utf8-byte-length",
            "4",
            "--artifact-dir",
            str(tmp_path / "p2-12"),
        ]
    )

    with pytest.raises(ValueError, match="two five-byte names"):
        goat_map_phase2_capture._validate_args(args)


def test_poller_isolation_cli_is_passive_and_requires_eight_minutes(
    tmp_path: Path,
) -> None:
    args = goat_map_phase2_capture._parser().parse_args(
        [
            "--mode",
            "poller-isolation",
            "--country",
            "NO",
            "--phase",
            "p2-12c-preflight-poller-isolation",
            "--mower-state",
            "paused",
            "--device-class",
            "2i0fns",
            "--quiet-seconds",
            "480",
            "--artifact-dir",
            str(tmp_path / "poller-isolation"),
        ]
    )

    goat_map_phase2_capture._validate_args(args)

    assert args.mode == "poller-isolation"
    assert args.mower_state == "paused"
    assert args.quiet_seconds == 480


def test_poller_isolation_cli_rejects_short_window(tmp_path: Path) -> None:
    args = goat_map_phase2_capture._parser().parse_args(
        [
            "--mode",
            "poller-isolation",
            "--country",
            "NO",
            "--phase",
            "p2-12c-preflight-poller-isolation",
            "--mower-state",
            "paused",
            "--device-class",
            "2i0fns",
            "--quiet-seconds",
            "479",
            "--artifact-dir",
            str(tmp_path / "poller-isolation"),
        ]
    )

    with pytest.raises(ValueError, match="480"):
        goat_map_phase2_capture._validate_args(args)
