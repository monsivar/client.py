"""Sanitized GOAT O1200 position capture samples."""

from __future__ import annotations

from typing import Any

# Observed in both getPos responses and onPos pushes from firmware 1.9.16.
# The valid charging-station form has not yet been observed on this O1200.
# The captured live-position mid is "0", while the static-map corpus uses "1";
# future map integration must establish that registration before exposing mid.
O1200_POSITION_DATA: dict[str, Any] = {
    "deebotPos": {"x": 5770, "y": 10646, "a": -55, "invalid": 0},
    "chargePos": [{"x": 0, "y": 0, "a": 0, "t": 1, "invalid": 1}],
    "mid": "0",
}

O1200_ON_POS_PAYLOAD: dict[str, Any] = {
    "header": {
        "tzm": 120,
        "ts": "1782388214909381938",
        "fwVer": "1.9.16",
    },
    "body": {"data": O1200_POSITION_DATA},
}
