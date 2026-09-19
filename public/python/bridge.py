from __future__ import annotations

import base64
import json
from pathlib import Path
from uuid import uuid4

import hexbin_core as v50
import compare_core as v55
import line_checksum_core as v12


SESSIONS: dict[str, dict] = {}


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False)


def _safe_name(name: str) -> str:
    cleaned = Path(name).name.replace("\x00", "")
    if not cleaned:
        raise ValueError("文件名不能为空。")
    return cleaned


def _write_upload(name: str, payload_b64: str) -> Path:
    upload_dir = Path("/tmp/hexbin_uploads")
    upload_dir.mkdir(parents=True, exist_ok=True)
    path = upload_dir / f"{uuid4().hex}_{_safe_name(name)}"
    path.write_bytes(base64.b64decode(payload_b64))
    return path


def _open_v50_file(path: Path):
    suffix = path.suffix.lower()
    if suffix == ".bin":
        return v50.ParsedBinFile.from_path(path)

    file_format = v50.detect_text_file_format(path)
    if file_format == "intel":
        records = v50.parse_intel_hex(path)
        if v50.detect_intel_80000_family(records):
            return v50.ParsedIntel80000File(path=path, records=records)
        return v50.ParsedHexFile(path=path, records=records)

    original_lines = [line for _, line in v50.read_srecord_lines(path)]
    try:
        records = v50.parse_srecord(path)
        checksum_mode = "standard"
    except ValueError as standard_error:
        records = v50.parse_srecord(path, checksum_mode="400000_s3fd")
        if not v50.detect_srec_400000_family(records):
            raise standard_error
        checksum_mode = "400000_s3fd"

    first_data_line = next((line for line in original_lines if line.startswith("S3")), "")
    if v50.detect_srec_14080000_family(records):
        return v50.ParsedSrec14080000File(path=path, records=records)
    if v50.detect_srec_800000_family(records):
        return v50.ParsedSrec800000File(path=path, records=records)
    if v50.detect_srec_200000_family(records):
        return v50.ParsedSrec200000File(path=path, records=records)
    if v50.detect_srec_400000_family(records):
        record_size = v50.SREC_400000_SOURCE_RECORD_DATA_SIZE if first_data_line.startswith("S3FD") else v50.SREC_400000_BIN_RECORD_DATA_SIZE
        return v50.ParsedSrec400000File(
            path=path,
            records=records,
            original_lines=original_lines,
            output_record_data_size=record_size,
            output_checksum_mode=checksum_mode,
        )
    return v50.ParsedSrecFile(path=path, records=records)


def _v50_metadata(item, original_name: str) -> dict:
    base = getattr(item, "display_base_address", item.min_address)
    display_size = max(getattr(item, "display_size", item.full_size), item.full_size)
    checksums = item.get_checksum_values(item.current_full_bin)
    checksum_rows = []
    for region in item.checksum_regions:
        current = checksums.get(region.segment_index, b"")
        original = item.original_checksum_values.get(region.segment_index, b"")
        checksum_rows.append({
            "segment": region.segment_index,
            "start": region.start_address,
            "end": region.end_address,
            "original": original.hex(" ").upper(),
            "current": current.hex(" ").upper(),
        })
    return {
        "name": original_name,
        "tool": "v50",
        "format": item.mode_name,
        "family": getattr(item, "family_label", "通用格式"),
        "checksumScheme": item.checksum_scheme_name,
        "baseAddress": base,
        "size": item.full_size,
        "displaySize": display_size,
        "segments": [{"start": start, "end": end, "size": end - start + 1} for start, end in item.segments],
        "checksums": checksum_rows,
        "endAddress": base + display_size - 1,
    }


def _v12_metadata(image, original_name: str) -> dict:
    base = image.display_base_address if image.display_base_address is not None else image.base_address
    end = image.display_end_address if image.display_end_address is not None else image.end_address
    return {
        "name": original_name,
        "tool": "v12",
        "format": image.source_format,
        "family": image.layout_label,
        "checksumScheme": "每行格式校验",
        "baseAddress": base,
        "size": len(image.data),
        "displaySize": len(image.data),
        "displayEndAddress": end,
        "logicalSegmentSize": image.logical_segment_size,
        "mirrorSpan": image.mirror_span,
        "segments": [{"start": base, "end": end, "size": len(image.data)}],
        "checksums": [],
        "checksumErrors": image.checksum_errors,
    }


def open_file(tool: str, name: str, payload_b64: str) -> str:
    path = _write_upload(name, payload_b64)
    if tool == "v50":
        item = _open_v50_file(path)
        metadata = _v50_metadata(item, name)
    elif tool == "v12":
        item = v12.load_image(path)
        metadata = _v12_metadata(item, name)
    else:
        raise ValueError("未知工具。")
    session_id = uuid4().hex
    SESSIONS[session_id] = {"tool": tool, "item": item, "name": name}
    metadata["sessionId"] = session_id
    return _json(metadata)


def _compare_metadata(item, original_name: str) -> dict:
    metadata = _v50_metadata(item, original_name)
    metadata.pop("sessionId", None)
    return metadata


def _compare_snapshot(session: dict) -> dict:
    comparison = v55.compare_parameter_files(session["left"], session["right"])
    session["comparison"] = comparison
    session["line_starts"] = v55.build_shared_line_starts(session["left"], session["right"])
    return v55.snapshot(comparison)


def open_compare(
    left_name: str,
    left_payload_b64: str,
    right_name: str,
    right_payload_b64: str,
) -> str:
    left = _open_v50_file(_write_upload(left_name, left_payload_b64))
    right = _open_v50_file(_write_upload(right_name, right_payload_b64))
    session_id = uuid4().hex
    session = {"tool": "v55", "left": left, "right": right, "left_name": left_name, "right_name": right_name}
    SESSIONS[session_id] = session
    return _json({
        "sessionId": session_id,
        "left": _compare_metadata(left, left_name),
        "right": _compare_metadata(right, right_name),
        "snapshot": _compare_snapshot(session),
    })


def _session(session_id: str) -> dict:
    try:
        return SESSIONS[session_id]
    except KeyError as exc:
        raise ValueError("文件会话已失效，请重新打开文件。") from exc


def _compare_session(session_id: str) -> dict:
    session = _session(session_id)
    if session.get("tool") != "v55":
        raise ValueError("当前文件不是 V55 对比会话。")
    return session


def _data(session: dict) -> bytearray:
    item = session["item"]
    return item.current_full_bin if session["tool"] == "v50" else item.data


def read_page(session_id: str, start: int, count: int) -> str:
    session = _session(session_id)
    data = _data(session)
    start = max(0, int(start))
    count = min(max(1, int(count)), 8192)
    end = min(len(data), start + count)
    return _json({"start": start, "end": end, "total": len(data), "bytes": list(data[start:end])})


def read_compare_page(session_id: str, start_address: int, count: int) -> str:
    session = _compare_session(session_id)
    count = min(max(1, int(count)), 512)
    return _json(v55.build_page(
        session["left"],
        session["right"],
        session["line_starts"],
        int(start_address),
        count,
    ))


def edit_byte(session_id: str, offset: int, value: int) -> str:
    session = _session(session_id)
    data = _data(session)
    offset = int(offset)
    value = int(value)
    if not 0 <= offset < len(data):
        raise ValueError("编辑位置超出文件范围。")
    if not 0 <= value <= 255:
        raise ValueError("字节值必须在 00 到 FF 之间。")
    data[offset] = value
    changed = {offset}
    if session["tool"] == "v50":
        item = session["item"]
        before = item.get_checksum_values(data)
        after = item.apply_checksum_rules(data)
        for index, new_value in after.items():
            if before.get(index, b"") != new_value:
                region = item.checksum_regions[index - 1]
                changed.update(range(region.checksum_offset, region.checksum_offset + region.checksum_size))
        metadata = _v50_metadata(item, session["name"])
    else:
        image = session["item"]
        if image.mirror_span is not None:
            first = image.mirror_base_offset
            second = first + image.mirror_span
            partner = None
            if first <= offset < first + image.mirror_span:
                partner = second + offset - first
            elif second <= offset < second + image.mirror_span:
                partner = first + offset - second
            if partner is not None and 0 <= partner < len(data):
                data[partner] = value
                changed.add(partner)
        metadata = _v12_metadata(image, session["name"])
    return _json({"changed": sorted(changed), "metadata": metadata})


def _edit_compare_side(session: dict, side: str, address: int, value: int) -> set[int]:
    if side not in {"left", "right"}:
        raise ValueError("未知的对比文件侧。")
    if not 0 <= value <= 255:
        raise ValueError("字节值必须在 00 到 FF 之间。")
    item = session[side]
    offset = int(address) - getattr(item, "display_base_address", item.min_address)
    if offset < 0 or offset >= len(item.current_full_bin) or offset not in item.present_offsets:
        raise ValueError(f"地址 0x{int(address):X} 在文件{side.upper()}中不是可编辑字节。")

    data = item.current_full_bin
    before = item.get_checksum_values(data)
    data[offset] = value
    changed_addresses = {int(address)}
    after = item.apply_checksum_rules(data)
    for index, new_value in after.items():
        if before.get(index, b"") == new_value:
            continue
        region = item.checksum_regions[index - 1]
        base = getattr(item, "display_base_address", item.min_address)
        changed_addresses.update(base + region.checksum_offset + offset for offset in range(region.checksum_size))
    return changed_addresses


def _prepare_compare_side(item) -> set[int]:
    data = item.current_full_bin
    before = bytes(data)
    item.mirror_first_segment_to_second(data)
    item.apply_checksum_rules(data)
    base = getattr(item, "display_base_address", item.min_address)
    return {
        base + offset
        for offset, (before_value, after_value) in enumerate(zip(before, data))
        if before_value != after_value
    }


def _compare_response(session: dict, changed_addresses: set[int]) -> dict:
    return {
        "changedAddresses": sorted(changed_addresses),
        "snapshot": _compare_snapshot(session),
        "left": _compare_metadata(session["left"], session["left_name"]),
        "right": _compare_metadata(session["right"], session["right_name"]),
    }


def edit_compare_byte(session_id: str, side: str, address: int, value: int) -> str:
    session = _compare_session(session_id)
    changed_addresses = _edit_compare_side(session, side, int(address), int(value))
    return _json(_compare_response(session, changed_addresses))


def recalculate_compare_side(session_id: str, side: str) -> str:
    session = _compare_session(session_id)
    if side not in {"left", "right"}:
        raise ValueError("未知的对比文件侧。")
    item = session[side]
    return _json(_compare_response(session, _prepare_compare_side(item)))


def search(session_id: str, needle_hex: str, start: int) -> str:
    session = _session(session_id)
    needle = v12.parse_hex_search(needle_hex)
    data = bytes(_data(session))
    start = max(0, int(start))
    found = data.find(needle, start)
    if found < 0 and start > 0:
        found = data.find(needle)
    return _json({"offset": found, "length": len(needle)})


def export_file(session_id: str, extension: str) -> str:
    session = _session(session_id)
    extension = extension.lower().lstrip(".")
    item = session["item"]
    stem = Path(session["name"]).stem

    if session["tool"] == "v50":
        item.mirror_first_segment_to_second(item.current_full_bin)
        item.apply_checksum_rules(item.current_full_bin)
        if extension == "bin":
            payload = bytes(item.current_full_bin)
        elif extension == "hex":
            if hasattr(item, "build_output_bytes"):
                payload = item.build_output_bytes(item.current_full_bin)
            else:
                payload = ("\n".join(item.build_output_lines(item.current_full_bin)) + "\n").encode("ascii")
        else:
            raise ValueError("主工具只能导出 HEX 或 BIN。")
    else:
        suffix = "." + extension
        output = Path("/tmp") / f"{uuid4().hex}{suffix}"
        if extension == "bin":
            v12.save_as_bin(output, item)
        elif extension == "hex":
            v12.save_as_intel_hex(output, item)
        elif extension in {"s19", "s28", "s37", "mot"}:
            v12.save_as_srecord(output, item, suffix)
        else:
            raise ValueError("不支持该导出格式。")
        payload = output.read_bytes()
        output.unlink(missing_ok=True)

    return _json({
        "name": f"{stem}_edited.{extension}",
        "mime": "application/octet-stream",
        "payload": base64.b64encode(payload).decode("ascii"),
    })


def export_compare(session_id: str, side: str, extension: str) -> str:
    session = _compare_session(session_id)
    if side not in {"left", "right"}:
        raise ValueError("未知的对比文件侧。")
    extension = extension.lower().lstrip(".")
    if extension not in {"hex", "bin"}:
        raise ValueError("V55 对比工具只能导出 HEX 或 BIN。")

    item = session[side]
    changed_addresses = _prepare_compare_side(item)
    if extension == "bin":
        payload = bytes(item.current_full_bin)
    elif hasattr(item, "build_output_bytes"):
        payload = item.build_output_bytes(item.current_full_bin)
    else:
        payload = ("\n".join(item.build_output_lines(item.current_full_bin)) + "\n").encode("ascii")

    stem = Path(session[f"{side}_name"]).stem
    result = _compare_response(session, changed_addresses)
    result.update({
        "name": f"{stem}_edited.{extension}",
        "mime": "application/octet-stream",
        "payload": base64.b64encode(payload).decode("ascii"),
    })
    return _json(result)
