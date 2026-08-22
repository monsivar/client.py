from __future__ import annotations

import argparse
import asyncio
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, MagicMock

import orjson
import pytest

from deebot_client.exceptions import DeviceVerificationRequiredError
from deebot_client.models import Credentials
from scripts import goat_map_refresh_diagnostic as diagnostic

if TYPE_CHECKING:
    from pathlib import Path

    from deebot_client.models import DeviceInfo


def test_select_device_accepts_only_supported_mqtt_device_without_goat_name() -> None:
    mower = cast(
        "DeviceInfo",
        SimpleNamespace(api={"class": "2i0fns", "deviceName": "O1200"}),
    )

    assert diagnostic._select_device([mower], None) is mower


def test_windows_diagnostic_uses_selector_event_loop() -> None:
    async def loop_supports_socket_readers() -> bool:
        loop = asyncio.get_running_loop()
        return type(loop) is asyncio.SelectorEventLoop

    assert diagnostic._run_with_compatible_event_loop(
        loop_supports_socket_readers(), platform="win32"
    )


def test_client_device_id_is_created_once_and_reused(tmp_path: Path) -> None:
    state_file = tmp_path / "client-state.json"
    first_generated = "a" * 32

    first = diagnostic.load_or_create_client_device_id(
        state_file, create_id=lambda: first_generated
    )
    second = diagnostic.load_or_create_client_device_id(
        state_file, create_id=lambda: "b" * 32
    )

    assert first == first_generated
    assert second == first_generated
    state = orjson.loads(state_file.read_bytes())
    assert state == {"version": 1, "client_device_id": first_generated}


@pytest.mark.parametrize(
    "state",
    [
        b"not-json",
        b'{"version":2,"client_device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
        b'{"version":1,"client_device_id":"invalid"}',
    ],
)
def test_client_device_id_rejects_invalid_state(tmp_path: Path, state: bytes) -> None:
    state_file = tmp_path / "client-state.json"
    state_file.write_bytes(state)

    with pytest.raises(ValueError, match="state file"):
        diagnostic.load_or_create_client_device_id(state_file)


def test_presence_renewal_cli_requires_isolated_factor_combination() -> None:
    args = diagnostic._parser().parse_args(
        [
            "--country",
            "NO",
            "--phase",
            "presence-renewal",
            "--mower-state",
            "mowing",
            "--jmq",
            "none",
            "--appping",
            "ngiot",
            "--get-mi",
            "none",
            "--renew-appping-after-seconds",
            "240",
            "--presence-total-seconds",
            "700",
            "--output",
            "renewal.json",
        ]
    )

    diagnostic._validate_args(args)

    args.jmq = "app-presence"
    with pytest.raises(ValueError, match="--jmq none"):
        diagnostic._validate_args(args)


def test_presence_renewal_cli_requires_both_timing_values() -> None:
    args = diagnostic._parser().parse_args(
        [
            "--country",
            "NO",
            "--phase",
            "presence-renewal",
            "--mower-state",
            "mowing",
            "--appping",
            "ngiot",
            "--renew-appping-after-seconds",
            "240",
            "--output",
            "renewal.json",
        ]
    )

    with pytest.raises(ValueError, match="requires both"):
        diagnostic._validate_args(args)


async def test_device_verification_error_requests_code_and_verifies() -> None:
    authenticator = MagicMock()
    authenticator.authenticate = AsyncMock(
        side_effect=DeviceVerificationRequiredError(
            "Please update to the latest version to continue."
        )
    )
    authenticator.request_device_verification_code = AsyncMock()
    authenticator.verify_device = AsyncMock(
        return_value=Credentials(
            token="secret-access-token",  # noqa: S106
            user_id="secret-user",
            expires_at=999,
        )
    )
    code_provider = AsyncMock(return_value=" 123456 ")

    await diagnostic.authenticate_with_device_verification(authenticator, code_provider)

    authenticator.request_device_verification_code.assert_awaited_once_with()
    code_provider.assert_awaited_once_with()
    authenticator.verify_device.assert_awaited_once_with("123456")


async def test_diagnostic_continues_after_verification_without_auth_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verification_code = "654321"
    account = "private@example.test"
    password = "private-password"  # noqa: S105
    access_token = "private-access-token"  # noqa: S105
    user_id = "private-user-id"
    state_file = tmp_path / "client-state.json"
    state_file.write_bytes(orjson.dumps({"version": 1, "client_device_id": "c" * 32}))
    args = argparse.Namespace(
        country="NO",
        phase="01-baseline",
        mower_state="mowing",
        jmq="none",
        appping="none",
        get_mi="none",
        device_class="2i0fns",
        baseline_seconds=0,
        observation_seconds=0,
        renew_appping_after_seconds=None,
        presence_total_seconds=None,
        connect_timeout=1,
        output=tmp_path / "report.json",
        client_state_file=state_file,
    )

    authenticator = MagicMock()
    authenticator.authenticate = AsyncMock(
        side_effect=DeviceVerificationRequiredError("verification required")
    )
    authenticator.request_device_verification_code = AsyncMock()
    authenticator.verify_device = AsyncMock(
        return_value=Credentials(token=access_token, user_id=user_id, expires_at=999)
    )
    authenticator.teardown = AsyncMock()
    authenticator_type = MagicMock(return_value=authenticator)
    monkeypatch.setattr(diagnostic, "Authenticator", authenticator_type)

    mower = SimpleNamespace(api={"class": "2i0fns", "deviceName": "GOAT O-series"})
    api = MagicMock()
    api.get_devices = AsyncMock(return_value=SimpleNamespace(mqtt=[mower]))
    monkeypatch.setattr(diagnostic, "ApiClient", MagicMock(return_value=api))

    report: dict[str, Any] = {
        "experiment": {"phase": "01-baseline"},
        "records": [],
        "sessions": {},
        "mid_correlation": {},
    }
    experiment = MagicMock()
    experiment.run = AsyncMock(return_value=report)
    experiment_type = MagicMock(return_value=experiment)
    monkeypatch.setattr(diagnostic, "GoatMapDiagnosticExperiment", experiment_type)
    code_provider = AsyncMock(return_value=verification_code)

    result = await diagnostic._run(
        args,
        account,
        password,
        verification_code_provider=code_provider,
    )

    authenticator.request_device_verification_code.assert_awaited_once_with()
    authenticator.verify_device.assert_awaited_once_with(verification_code)
    api.get_devices.assert_awaited_once_with()
    experiment.run.assert_awaited_once()
    authenticator.teardown.assert_awaited_once_with()
    assert experiment_type.call_args.kwargs["device_id"] == "c" * 32

    serialized = orjson.dumps(result).decode()
    for secret in (verification_code, account, password, access_token, user_id):
        assert secret not in serialized
