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


def test_v55_compare_edit_and_refresh() -> None:
    original = bytearray((ROOT / "704_test.bin").read_bytes())
    changed = bytearray(original)
    changed[0] ^= 1
    comparison = json.loads(
        bridge.open_compare(
            "left.bin",
            base64.b64encode(original).decode("ascii"),
            "right.bin",
            base64.b64encode(changed).decode("ascii"),
        )
    )
    assert comparison["snapshot"]["parameterDifferenceCount"] == 1
    assert comparison["snapshot"]["totalDifferenceCount"] == 1

    page = json.loads(bridge.read_compare_page(comparison["sessionId"], 0, 1))
    assert page["rows"][0]["left"][0] != page["rows"][0]["right"][0]

    edit = json.loads(
        bridge.edit_compare_byte(
            comparison["sessionId"],
            "right",
            0x80000,
            original[0],
        )
    )
    assert edit["snapshot"]["parameterDifferenceCount"] == 0
    assert edit["snapshot"]["checksumDifferenceCount"] == 1


def test_v55_recalculate_syncs_mirror_before_checksum() -> None:
    original = bytearray((ROOT / "sample_from_bin_saved.hex").read_bytes())
    comparison = json.loads(
        bridge.open_compare(
            "left.hex",
            base64.b64encode(original).decode("ascii"),
            "right.hex",
            base64.b64encode(original).decode("ascii"),
        )
    )
    session = bridge.SESSIONS[comparison["sessionId"]]
    item = session["left"]
    if len(item.checksum_regions) < 2:
        raise AssertionError("测试文件没有可用于验证镜像同步的双段结构。")
    first = item.checksum_regions[0]
    second = item.checksum_regions[1]
    item.current_full_bin[second.start_offset] ^= 1

    result = json.loads(bridge.recalculate_compare_side(comparison["sessionId"], "left"))
    assert item.current_full_bin[second.start_offset] == item.current_full_bin[first.start_offset]
    assert result["snapshot"]["totalDifferenceCount"] == 0


def test_v55_export_returns_refreshed_compare_state() -> None:
    original = bytearray((ROOT / "sample_from_bin_saved.hex").read_bytes())
    changed = bytearray(original)
    comparison = json.loads(
        bridge.open_compare(
            "left.hex",
            base64.b64encode(original).decode("ascii"),
            "right.hex",
            base64.b64encode(changed).decode("ascii"),
        )
    )
    session = bridge.SESSIONS[comparison["sessionId"]]
    item = session["left"]
    if len(item.checksum_regions) < 2:
        raise AssertionError("测试文件没有可用于验证导出状态的双段结构。")
    second = item.checksum_regions[1]
    item.current_full_bin[second.start_offset] ^= 1
    exported = json.loads(bridge.export_compare(comparison["sessionId"], "left", "bin"))
    assert exported["snapshot"]["totalDifferenceCount"] == 0
    assert exported["name"] == "left_edited.bin"
    assert base64.b64decode(exported["payload"]) == bytes(item.current_full_bin)


if __name__ == "__main__":
    test_v50_checksum_and_roundtrip()
    test_v11_line_checksum()
    test_v55_compare_edit_and_refresh()
    test_v55_recalculate_syncs_mirror_before_checksum()
    test_v55_export_returns_refreshed_compare_state()
    print("core regression tests passed")
