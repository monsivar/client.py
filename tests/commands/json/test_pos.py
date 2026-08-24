from __future__ import annotations

from typing import Any

import pytest

from deebot_client.commands.json import GetPos
from deebot_client.events import Position, PositionsEvent
from deebot_client.message import HandlingResult, HandlingState
from deebot_client.rs.map import PositionType
from tests.fixtures.o1200_position import O1200_POSITION_DATA
from tests.helpers import get_request_json, get_success_body

from . import assert_command


@pytest.mark.parametrize(
    ("response_data", "expected_positions"),
    [
        (
            {"chargePos": {"x": 5, "y": 9}, "deebotPos": {"x": 1, "y": 5, "a": 85}},
            [
                Position(type=PositionType.DEEBOT, x=1, y=5, a=85),
                Position(type=PositionType.CHARGER, x=5, y=9, a=0),
            ],
        ),
        (
            {
                "chargePos": [{"a": -91, "invalid": 0, "t": 3, "x": 5, "y": 649}],
                "deebotPos": {"a": 0, "invalid": 1, "x": 0, "y": 0},
            },
            [Position(type=PositionType.CHARGER, x=5, y=649, a=-91)],
        ),
        (
            {
                "deebotPos": {"x": -379, "y": -359, "a": 43, "invalid": 0},
                "chargePos": [{"x": -379, "y": -359, "a": 43, "t": 3, "invalid": 0}],
            },
            [
                Position(type=PositionType.DEEBOT, x=-379, y=-359, a=43),
                Position(type=PositionType.CHARGER, x=-379, y=-359, a=43),
            ],
        ),
    ],
)
async def test_GetPos(
    response_data: dict[str, Any], expected_positions: list[Position]
) -> None:
    json, firmware_event = get_request_json(get_success_body(response_data))
    expected_events = (
        firmware_event,
        PositionsEvent(positions=expected_positions),
    )
    await assert_command(GetPos(), json, expected_events)


async def test_GetPos_o1200_capture() -> None:
    """A captured O1200 position must publish the mower, not the invalid dock."""
    json, firmware_event = get_request_json(get_success_body(O1200_POSITION_DATA))

    await assert_command(
        GetPos(),
        json,
        (
            firmware_event,
            PositionsEvent(
                positions=[Position(type=PositionType.DEEBOT, x=5770, y=10646, a=-55)]
            ),
        ),
        device_class="2i0fns",
    )


async def test_GetPos_all_positions_invalid() -> None:
    """Invalid entries must not emit mower or charging-station positions."""
    data = {
        "deebotPos": {"x": 0, "y": 0, "a": 0, "invalid": 1},
        "chargePos": [{"x": 0, "y": 0, "a": 0, "invalid": 1}],
    }
    json, firmware_event = get_request_json(get_success_body(data))

    await assert_command(
        GetPos(),
        json,
        firmware_event,
        handling_result=HandlingResult(HandlingState.ANALYSE_LOGGED),
    )


async def test_GetPos_invalid_two_is_not_published() -> None:
    """O1200 nonzero invalid statuses are not emitted as positions."""
    data = {
        "deebotPos": {"x": 10, "y": 20, "a": 30, "invalid": 0},
        "chargePos": [{"x": 99, "y": 88, "a": 77, "invalid": 2}],
    }
    json, firmware_event = get_request_json(get_success_body(data))

    await assert_command(
        GetPos(),
        json,
        (
            firmware_event,
            PositionsEvent(
                positions=[Position(type=PositionType.DEEBOT, x=10, y=20, a=30)]
            ),
        ),
    )

    invalid_data: dict[str, Any] = {
        "deebotPos": {"x": 10, "y": 20, "a": 30, "invalid": 2},
        "chargePos": [{"x": 99, "y": 88, "a": 77, "invalid": 2}],
    }
    json, firmware_event = get_request_json(get_success_body(invalid_data))

    await assert_command(
        GetPos(),
        json,
        firmware_event,
        handling_result=HandlingResult(HandlingState.ANALYSE_LOGGED),
    )
