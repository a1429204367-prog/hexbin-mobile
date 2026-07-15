from __future__ import annotations

import base64
import json
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
ROOT = PROJECT.parent
sys.path.insert(0, str(PROJECT / "public" / "python"))

import bridge


def open_sample(tool: str, name: str) -> dict:
    payload = base64.b64encode((ROOT / name).read_bytes()).decode("ascii")
    return json.loads(bridge.open_file(tool, name, payload))


def test_v50_checksum_and_roundtrip() -> None:
    metadata = open_sample("v50", "704_test.bin")
    page = json.loads(bridge.read_page(metadata["sessionId"], 0, 1))
    edit = json.loads(bridge.edit_byte(metadata["sessionId"], 0, page["bytes"][0] ^ 1))
    assert edit["metadata"]["checksums"][0]["current"] == "A4 17"

    exported = json.loads(bridge.export_file(metadata["sessionId"], "hex"))
    reopened = json.loads(
        bridge.open_file("v50", exported["name"], exported["payload"])
    )
    assert reopened["checksums"][0]["current"] == "A4 17"


def test_v11_line_checksum() -> None:
    metadata = open_sample("v11", "SHSJ01-B(1).hex")
    json.loads(bridge.edit_byte(metadata["sessionId"], 0, 0x51))
    exported = json.loads(bridge.export_file(metadata["sessionId"], "hex"))
    output = base64.b64decode(exported["payload"]).decode("ascii")
    expected = ":201000005105002019100010000000009910001000180400000100001149124A124B00F048"
    assert expected in output.splitlines()


if __name__ == "__main__":
    test_v50_checksum_and_roundtrip()
    test_v11_line_checksum()
    print("core regression tests passed")
