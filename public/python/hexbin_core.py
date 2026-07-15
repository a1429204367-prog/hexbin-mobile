from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
tk = None
filedialog = messagebox = ttk = ScrolledText = None


BYTES_PER_LINE = 16
EDITOR_HEADER_LINES = 0
MONOSPACE_FONT = "Courier New"
EDITOR_FONT_SIZE = 12
HEX_GROUP_BREAK_INDEX = 8
HEX_GROUP_EXTRA_SPACES = 1
SEGMENT_BIN_SIZE = 16_384
CHECKSUM_START_INDEX = 16_380
CHECKSUM_BASE = 364_756_291
CHECKSUM_CONSTANTS = (586_685, 584_527, 581_966, 582_912)
DUAL_GROUP_SEGMENT_SIZE = 65_536
DUAL_GROUP_CHECKSUM_OFFSET = 65_534
SREC_200000_BASE = 0x200000
SREC_200000_MIRROR_OFFSET = 0x20000
SREC_200000_SECOND_BASE = SREC_200000_BASE + SREC_200000_MIRROR_OFFSET
SREC_200000_TOTAL_IMAGE_SIZE = 0x30000
SREC_200000_RECORD_DATA_SIZE = 250
SREC_200000_CHECKSUM_BASE = 258_372_990
SREC_200000_CHECKSUM_CONSTANTS = (636_487, 630_714, 644_430, 670_850)
SREC_800000_BASE = 0x800000
SREC_800000_MIRROR_OFFSET = 0x8000
SREC_800000_SECOND_BASE = SREC_800000_BASE + SREC_800000_MIRROR_OFFSET
SREC_800000_TOTAL_IMAGE_SIZE = 0x10000
SREC_800000_RECORD_DATA_SIZE = 250
SREC_400000_BASE = 0x400000
SREC_400000_BIN_SIZE = SEGMENT_BIN_SIZE
SREC_400000_MIRROR_OFFSET = 0x8000
SREC_400000_IMAGE_SIZE = 0xC000
SREC_400000_SOURCE_RECORD_DATA_SIZE = 248
SREC_400000_BIN_RECORD_DATA_SIZE = 128
SREC_14080000_BASE = 0x14080000
SREC_14080000_START = 0x1407FF28
SREC_14080000_PREFIX_PAD = 216
SREC_14080000_IMAGE_SIZE = 0x20000
SREC_14080000_RECORD_DATA_SIZE = 250
INTEL_80000_BASE = 0x80000
INTEL_80000_SEGMENT_SIZE = 0x8000
INTEL_80000_TOTAL_SIZE = 0x10000
INTEL_80000_RECORD_DATA_SIZE = 0x80
A020_BASE_EXT = 0xA020
BIN_FAMILY_CODE_OFFSET = 0x0D
BIN_FAMILY_CODE_MAP = {
    0x01: "778_one",
    0x02: "60000000",
    0x03: "1161_one",
    0x04: "1161_two",
    0x05: "1001_one",
    0x06: "1001_two",
    0x07: "704",
    0x08: "800000",
    0x09: "710",
}

EDITOR_HEX_START = 10
EDITOR_HEX_WIDTH = BYTES_PER_LINE * 3 - 1 + HEX_GROUP_EXTRA_SPACES
EDITOR_ASCII_START = EDITOR_HEX_START + EDITOR_HEX_WIDTH + 2


@dataclass
class HexRecord:
    byte_count: int
    address: int
    record_type: int
    data: bytes
    checksum: int
    line_number: int


@dataclass
class SRecord:
    record_type: str
    count: int
    address: int
    data: bytes
    checksum: int
    line_number: int


@dataclass
class ChecksumRegion:
    segment_index: int
    start_address: int
    end_address: int
    start_offset: int
    checksum_offset: int
    block_size: int
    checksum_size: int
    scheme_name: str

    @property
    def checksum_addresses(self) -> tuple[int, ...]:
        base = self.start_address + self.checksum_offset - self.start_offset
        return tuple(base + index for index in range(self.checksum_size))


@dataclass
class EditTarget:
    offset: int
    region: str
    nibble: int = 0


def intel_hex_checksum(byte_count: int, address: int, record_type: int, data: bytes) -> int:
    total = byte_count
    total += (address >> 8) & 0xFF
    total += address & 0xFF
    total += record_type
    total += sum(data)
    return (-total) & 0xFF


def encode_record(record: HexRecord, data_override: bytes | None = None) -> str:
    data = record.data if data_override is None else data_override
    checksum = intel_hex_checksum(record.byte_count, record.address, record.record_type, data)
    return f":{record.byte_count:02X}{record.address:04X}{record.record_type:02X}{data.hex().upper()}{checksum:02X}"


def parse_intel_hex(path: Path) -> list[HexRecord]:
    records: list[HexRecord] = []
    with path.open("r", encoding="ascii") as fp:
        for line_number, raw in enumerate(fp, start=1):
            line = raw.strip()
            if not line:
                continue
            if not line.startswith(":"):
                raise ValueError(f"第 {line_number} 行不是有效的 Intel HEX 记录。")
            try:
                byte_count = int(line[1:3], 16)
                address = int(line[3:7], 16)
                record_type = int(line[7:9], 16)
                data = bytes.fromhex(line[9 : 9 + byte_count * 2])
                checksum = int(line[9 + byte_count * 2 : 11 + byte_count * 2], 16)
            except ValueError as exc:
                raise ValueError(f"第 {line_number} 行格式错误。") from exc

            if intel_hex_checksum(byte_count, address, record_type, data) != checksum:
                raise ValueError(f"第 {line_number} 行 Intel HEX 校验错误。")

            records.append(
                HexRecord(
                    byte_count=byte_count,
                    address=address,
                    record_type=record_type,
                    data=data,
                    checksum=checksum,
                    line_number=line_number,
                )
            )
            if record_type == 1:
                break
    return records


def srecord_address_length(record_type: str) -> int:
    if record_type in {"0", "1", "5", "9"}:
        return 2
    if record_type in {"2", "8"}:
        return 3
    if record_type in {"3", "7"}:
        return 4
    raise ValueError(f"不支持的 S Record 类型: S{record_type}")


def srecord_checksum(record_type: str, address: int, data: bytes) -> int:
    address_length = srecord_address_length(record_type)
    count = address_length + len(data) + 1
    total = count
    for shift in range((address_length - 1) * 8, -1, -8):
        total += (address >> shift) & 0xFF
    total += sum(data)
    return (~total) & 0xFF


def srecord_checksum_for_mode(record_type: str, address: int, data: bytes, checksum_mode: str = "standard") -> int:
    checksum = srecord_checksum(record_type, address, data)
    if checksum_mode == "400000_s3fd" and record_type == "3":
        checksum = (checksum - 0x40) & 0xFF
    return checksum


def encode_srecord(record: SRecord, data_override: bytes | None = None, *, checksum_mode: str = "standard") -> str:
    data = record.data if data_override is None else data_override
    address_length = srecord_address_length(record.record_type)
    count = address_length + len(data) + 1
    checksum = srecord_checksum_for_mode(record.record_type, record.address, data, checksum_mode)
    address_hex = f"{record.address:0{address_length * 2}X}"
    return f"S{record.record_type}{count:02X}{address_hex}{data.hex().upper()}{checksum:02X}"


def read_srecord_lines(path: Path) -> list[tuple[int, str]]:
    cleaned: list[tuple[int, str]] = []
    with path.open("r", encoding="ascii", errors="ignore") as fp:
        for line_number, raw in enumerate(fp, start=1):
            line = raw.strip().upper()
            if not line:
                continue
            marker = line.find("S")
            if marker < 0:
                continue
            line = line[marker:]
            if len(line) < 4:
                raise ValueError(f"第 {line_number} 行不是有效的 S Record 记录。")
            try:
                count = int(line[2:4], 16)
            except ValueError as exc:
                raise ValueError(f"第 {line_number} 行 S Record 格式错误。") from exc
            expected_length = 4 + count * 2
            if len(line) < expected_length:
                raise ValueError(f"第 {line_number} 行 S Record 长度错误。")
            cleaned.append((line_number, line[:expected_length]))
    return cleaned


def parse_srecord(path: Path, *, checksum_mode: str = "standard") -> list[SRecord]:
    records: list[SRecord] = []
    for line_number, line in read_srecord_lines(path):
        if not line.startswith("S") or len(line) < 4:
            raise ValueError(f"第 {line_number} 行不是有效的 S Record 记录。")
        record_type = line[1].upper()
        try:
            address_length = srecord_address_length(record_type)
            count = int(line[2:4], 16)
            payload_hex = line[4:]
            payload = bytes.fromhex(payload_hex)
        except ValueError as exc:
            raise ValueError(f"第 {line_number} 行 S Record 格式错误。") from exc

        if len(payload) != count:
            raise ValueError(f"第 {line_number} 行 S Record 长度错误。")
        if count < address_length + 1:
            raise ValueError(f"第 {line_number} 行 S Record 数据长度错误。")

        address = int.from_bytes(payload[:address_length], "big")
        data = payload[address_length:-1]
        checksum = payload[-1]

        if srecord_checksum_for_mode(record_type, address, data, checksum_mode) != checksum:
            raise ValueError(f"第 {line_number} 行 S Record 校验错误。")

        records.append(
            SRecord(
                record_type=record_type,
                count=count,
                address=address,
                data=data,
                checksum=checksum,
                line_number=line_number,
            )
        )
    return records


def safe_ascii(value: int) -> str:
    return chr(value) if 32 <= value <= 126 else "."


def format_address_field(address: int) -> str:
    return f"{address:X}".rjust(8)


def format_address_text(address: int) -> str:
    return f"0x{address:X}"


def hex_cell_start_column(byte_index: int) -> int:
    extra_gap = HEX_GROUP_EXTRA_SPACES if byte_index >= HEX_GROUP_BREAK_INDEX else 0
    return EDITOR_HEX_START + byte_index * 3 + extra_gap


def format_hex_columns(items: list[str]) -> str:
    if not items:
        return ""
    first_group = " ".join(items[:HEX_GROUP_BREAK_INDEX])
    second_group = " ".join(items[HEX_GROUP_BREAK_INDEX:])
    if not second_group:
        return first_group
    return first_group + (" " * (1 + HEX_GROUP_EXTRA_SPACES)) + second_group


def format_editor_line(bin_data: bytes | bytearray, base_address: int, line_index: int) -> str:
    offset = line_index * BYTES_PER_LINE
    chunk = bin_data[offset : offset + BYTES_PER_LINE]
    address = base_address + offset
    hex_part = format_hex_columns([f"{value:02X}" for value in chunk]).ljust(EDITOR_HEX_WIDTH)
    ascii_part = "".join(safe_ascii(value) for value in chunk).ljust(BYTES_PER_LINE)
    return f"{format_address_field(address)}: {hex_part} |{ascii_part}|"


def format_editor_header_line() -> str:
    hex_labels = format_hex_columns([f"{index:X}".rjust(2) for index in range(BYTES_PER_LINE)]).ljust(EDITOR_HEX_WIDTH)
    ascii_labels = " " * BYTES_PER_LINE
    return f"{'Offset'.ljust(8)}: {hex_labels} |{ascii_labels}|"


def format_editor_text(bin_data: bytes | bytearray, base_address: int) -> str:
    line_count = (len(bin_data) + BYTES_PER_LINE - 1) // BYTES_PER_LINE
    return "\n".join(format_editor_line(bin_data, base_address, line_index) for line_index in range(line_count))


def detect_text_file_format(path: Path) -> str:
    with path.open("r", encoding="ascii", errors="strict") as fp:
        for raw in fp:
            line = raw.strip()
            if not line:
                continue
            if line.startswith(":"):
                return "intel"
            if line.startswith("S"):
                return "srec"
            break
    raise ValueError("无法识别文件格式，只支持 Intel HEX、S Record 或 BIN。")


def calculate_200000_checksum(bin_data: bytes | bytearray) -> bytes:
    if len(bin_data) < 4:
        raise ValueError("200000 总校验要求数据长度至少为 4 字节。")

    sums = [0, 0, 0, 0]
    for index in range(len(bin_data) - 4):
        sums[index % 4] += bin_data[index]

    value = SREC_200000_CHECKSUM_BASE
    value += (SREC_200000_CHECKSUM_CONSTANTS[0] - sums[0]) << 24
    value += (SREC_200000_CHECKSUM_CONSTANTS[1] - sums[1]) << 16
    value += (SREC_200000_CHECKSUM_CONSTANTS[2] - sums[2]) << 8
    value += SREC_200000_CHECKSUM_CONSTANTS[3] - sums[3]
    value %= 2**32
    return bytes(
        (
            (value >> 24) & 0xFF,
            (value >> 16) & 0xFF,
            (value >> 8) & 0xFF,
            value & 0xFF,
        )
    )


def detect_srec_200000_family(records: list[SRecord]) -> bool:
    memory: dict[int, int] = {}
    for record in records:
        if record.record_type != "3":
            continue
        for index, value in enumerate(record.data):
            address = record.address + index
            if address in memory and memory[address] != value:
                return False
            memory[address] = value

    if not memory:
        return False

    min_address = min(memory)
    max_address = max(memory)
    if min_address < SREC_200000_BASE or max_address >= SREC_200000_BASE + SREC_200000_TOTAL_IMAGE_SIZE:
        return False

    second_non_ff_addresses = [
        address for address, value in memory.items() if address >= SREC_200000_SECOND_BASE and value != 0xFF
    ]
    if not second_non_ff_addresses:
        return False

    bin_length = max(second_non_ff_addresses) - SREC_200000_SECOND_BASE + 1
    if bin_length < 4 or bin_length > SREC_200000_MIRROR_OFFSET:
        return False

    mismatch_count = 0
    for offset in range(bin_length):
        first_value = memory.get(SREC_200000_BASE + offset, 0xFF)
        second_value = memory.get(SREC_200000_SECOND_BASE + offset, 0xFF)
        if first_value != second_value:
            mismatch_count += 1
            if mismatch_count > 16:
                break
    if mismatch_count > 16:
        first_image = bytearray(memory.get(SREC_200000_BASE + offset, 0xFF) for offset in range(bin_length))
        second_image = bytearray(memory.get(SREC_200000_SECOND_BASE + offset, 0xFF) for offset in range(bin_length))
        if first_image[-4:] != calculate_200000_checksum(first_image) and second_image[-4:] != calculate_200000_checksum(second_image):
            return False
    return True


def detect_srec_800000_family(records: list[SRecord]) -> bool:
    memory: dict[int, int] = {}
    for record in records:
        if record.record_type != "3":
            continue
        for index, value in enumerate(record.data):
            address = record.address + index
            if address in memory and memory[address] != value:
                return False
            memory[address] = value

    if not memory:
        return False

    min_address = min(memory)
    max_address = max(memory)
    if min_address < SREC_800000_BASE or max_address >= SREC_800000_BASE + SREC_800000_TOTAL_IMAGE_SIZE:
        return False

    first_non_ff_addresses = [
        address
        for address, value in memory.items()
        if SREC_800000_BASE <= address < SREC_800000_SECOND_BASE and value != 0xFF
    ]
    second_non_ff_addresses = [
        address for address, value in memory.items() if address >= SREC_800000_SECOND_BASE and value != 0xFF
    ]
    if not first_non_ff_addresses and not second_non_ff_addresses:
        return False

    if second_non_ff_addresses:
        bin_length = max(second_non_ff_addresses) - SREC_800000_SECOND_BASE + 1
        if bin_length < 4 or bin_length > SREC_800000_MIRROR_OFFSET:
            return False

        mismatch_count = 0
        for offset in range(bin_length):
            first_value = memory.get(SREC_800000_BASE + offset, 0xFF)
            second_value = memory.get(SREC_800000_SECOND_BASE + offset, 0xFF)
            if first_value != second_value:
                mismatch_count += 1
                if mismatch_count > 16:
                    break
        if mismatch_count > 16:
            first_image = bytearray(memory.get(SREC_800000_BASE + offset, 0xFF) for offset in range(bin_length))
            second_image = bytearray(memory.get(SREC_800000_SECOND_BASE + offset, 0xFF) for offset in range(bin_length))
            if first_image[-4:] != calculate_200000_checksum(first_image) and second_image[-4:] != calculate_200000_checksum(second_image):
                return False
    else:
        bin_length = max(first_non_ff_addresses) - SREC_800000_BASE + 1
        if bin_length < 4 or bin_length > SREC_800000_MIRROR_OFFSET:
            return False
    return True


def detect_srec_14080000_family(records: list[SRecord]) -> bool:
    memory: dict[int, int] = {}
    record_starts: list[int] = []
    for record in records:
        if record.record_type != "3":
            continue
        record_starts.append(record.address)
        for index, value in enumerate(record.data):
            address = record.address + index
            if address in memory and memory[address] != value:
                return False
            memory[address] = value

    if not memory:
        return False

    min_address = min(memory)
    max_address = max(memory)
    expected_max = (
        SREC_14080000_START
        + ((SREC_14080000_PREFIX_PAD + SREC_14080000_IMAGE_SIZE + SREC_14080000_RECORD_DATA_SIZE - 1) // SREC_14080000_RECORD_DATA_SIZE)
        * SREC_14080000_RECORD_DATA_SIZE
        - 1
    )
    if min_address < SREC_14080000_START or max_address > expected_max:
        return False

    first_addresses = [address for address in memory if SREC_14080000_BASE <= address < SREC_14080000_BASE + 0x10000]
    second_addresses = [address for address in memory if SREC_14080000_BASE + 0x10000 <= address < SREC_14080000_BASE + 0x20000]
    has_expected_start = SREC_14080000_START in record_starts or SREC_14080000_BASE in record_starts
    return has_expected_start and bool(first_addresses and second_addresses)


def detect_srec_400000_family(records: list[SRecord]) -> bool:
    memory: dict[int, int] = {}
    record_starts: list[int] = []
    max_record_size = 0
    for record in records:
        if record.record_type != "3":
            continue
        record_starts.append(record.address)
        max_record_size = max(max_record_size, len(record.data))
        for index, value in enumerate(record.data):
            address = record.address + index
            if address in memory and memory[address] != value:
                return False
            memory[address] = value

    if not memory or SREC_400000_BASE not in record_starts:
        return False

    padded_span = ((SREC_400000_IMAGE_SIZE + max(max_record_size, 1) - 1) // max(max_record_size, 1)) * max(max_record_size, 1)
    min_address = min(memory)
    max_address = max(memory)
    if min_address < SREC_400000_BASE or max_address >= SREC_400000_BASE + padded_span:
        return False

    gap_start = SREC_400000_BASE + SREC_400000_BIN_SIZE
    gap_end = SREC_400000_BASE + SREC_400000_MIRROR_OFFSET
    second_start = gap_end
    second_end = SREC_400000_BASE + SREC_400000_IMAGE_SIZE

    first_non_ff = False
    second_non_ff = False
    for address, value in memory.items():
        if gap_start <= address < gap_end and value != 0xFF:
            return False
        if address >= second_end and value != 0xFF:
            return False
        if SREC_400000_BASE <= address < gap_start and value != 0xFF:
            first_non_ff = True
        if second_start <= address < second_end and value != 0xFF:
            second_non_ff = True

    if not (first_non_ff and second_non_ff):
        return False
    return True


def build_sparse_s3_lines(
    image: bytes | bytearray,
    *,
    start_address: int,
    record_data_size: int,
    checksum_mode: str = "standard",
) -> list[str]:
    lines: list[str] = []
    for offset in range(0, len(image), record_data_size):
        chunk = bytearray([0xFF] * record_data_size)
        src = image[offset : offset + record_data_size]
        chunk[: len(src)] = src
        if all(value == 0xFF for value in chunk):
            continue
        lines.append(
            encode_srecord(
                SRecord(
                    record_type="3",
                    count=0,
                    address=start_address + offset,
                    data=bytes(chunk),
                    checksum=0,
                    line_number=0,
                ),
                checksum_mode=checksum_mode,
            )
        )
    lines.append(encode_srecord(SRecord(record_type="7", count=0, address=0, data=b"", checksum=0, line_number=0)))
    return lines


def build_400000_family_lines(
    bin_data: bytes | bytearray,
    *,
    record_data_size: int,
    checksum_mode: str,
) -> list[str]:
    image = bytearray([0xFF] * SREC_400000_IMAGE_SIZE)
    image[:SREC_400000_BIN_SIZE] = bin_data[:SREC_400000_BIN_SIZE]
    second_start = SREC_400000_MIRROR_OFFSET
    image[second_start : second_start + SREC_400000_BIN_SIZE] = bin_data[:SREC_400000_BIN_SIZE]
    return build_sparse_s3_lines(
        image,
        start_address=SREC_400000_BASE,
        record_data_size=record_data_size,
        checksum_mode=checksum_mode,
    )


def build_800000_family_lines(bin_data: bytes | bytearray) -> list[str]:
    image = bytearray([0xFF] * SREC_800000_TOTAL_IMAGE_SIZE)
    image[: len(bin_data)] = bin_data[: len(bin_data)]
    image[SREC_800000_MIRROR_OFFSET : SREC_800000_MIRROR_OFFSET + len(bin_data)] = bin_data[: len(bin_data)]

    lines: list[str] = []
    for offset in range(0, len(image), SREC_800000_RECORD_DATA_SIZE):
        chunk = bytes(image[offset : offset + SREC_800000_RECORD_DATA_SIZE])
        if not chunk or all(value == 0xFF for value in chunk):
            continue
        lines.append(
            encode_srecord(
                SRecord(
                    record_type="3",
                    count=0,
                    address=SREC_800000_BASE + offset,
                    data=chunk,
                    checksum=0,
                    line_number=0,
                )
            )
        )
    lines.append(encode_srecord(SRecord(record_type="7", count=0, address=0, data=b"", checksum=0, line_number=0)))
    return lines


def detect_intel_80000_family(records: list[HexRecord]) -> bool:
    if not records:
        return False
    first_record = next((record for record in records if record.record_type != 1), None)
    if first_record is None or first_record.record_type != 2 or first_record.data != bytes.fromhex("8000"):
        return False

    data_records = [record for record in records if record.record_type == 0]
    if len(data_records) != INTEL_80000_TOTAL_SIZE // INTEL_80000_RECORD_DATA_SIZE:
        return False
    if any(record.byte_count != INTEL_80000_RECORD_DATA_SIZE for record in data_records):
        return False
    if data_records[0].address != 0 or data_records[-1].address != 0xFF80:
        return False
    return all(record.address == index * INTEL_80000_RECORD_DATA_SIZE for index, record in enumerate(data_records))


def calculate_intel_80000_checksum(
    segment_data: bytes | bytearray,
    *,
    seed: int,
) -> bytes:
    if len(segment_data) != INTEL_80000_SEGMENT_SIZE:
        raise ValueError("80000 两字节总校验要求第一段长度必须是 32768 字节。")
    sum_even = sum(segment_data[index] for index in range(0, INTEL_80000_SEGMENT_SIZE - 2, 2))
    sum_odd = sum(segment_data[index] for index in range(1, INTEL_80000_SEGMENT_SIZE - 2, 2))
    value = (seed - ((sum_even << 8) + sum_odd)) & 0xFFFF
    return bytes(((value >> 8) & 0xFF, value & 0xFF))


def derive_intel_80000_checksum_seed(segment_data: bytes | bytearray) -> int:
    if len(segment_data) != INTEL_80000_SEGMENT_SIZE:
        raise ValueError("80000 两字节总校验要求第一段长度必须是 32768 字节。")
    existing = (segment_data[-2] << 8) | segment_data[-1]
    sum_even = sum(segment_data[index] for index in range(0, INTEL_80000_SEGMENT_SIZE - 2, 2))
    sum_odd = sum(segment_data[index] for index in range(1, INTEL_80000_SEGMENT_SIZE - 2, 2))
    return (existing + ((sum_even << 8) + sum_odd)) & 0xFFFF


def build_intel_80000_hex_lines(bin_data: bytes | bytearray) -> list[str]:
    if len(bin_data) != INTEL_80000_SEGMENT_SIZE:
        raise ValueError("80000 规则 BIN 长度必须是 32768 字节。")

    mirrored = bytes(bin_data) + bytes(bin_data)
    lines: list[str] = [
        encode_record(
            HexRecord(
                byte_count=2,
                address=0,
                record_type=2,
                data=bytes.fromhex("8000"),
                checksum=0,
                line_number=0,
            )
        )
    ]
    for address in range(0, INTEL_80000_TOTAL_SIZE, INTEL_80000_RECORD_DATA_SIZE):
        chunk = mirrored[address : address + INTEL_80000_RECORD_DATA_SIZE]
        lines.append(
            encode_record(
                HexRecord(
                    byte_count=len(chunk),
                    address=address,
                    record_type=0,
                    data=chunk,
                    checksum=0,
                    line_number=0,
                )
            )
        )
    lines.append(encode_record(HexRecord(byte_count=0, address=0, record_type=1, data=b"", checksum=0, line_number=0)))
    return lines


def build_shifted_mirrored_s3_lines(
    bin_data: bytes | bytearray,
    *,
    start_address: int,
    prefix_pad: int,
    record_data_size: int,
) -> list[str]:
    image = bytearray([0xFF] * (len(bin_data) * 2))
    image[: len(bin_data)] = bin_data[: len(bin_data)]
    image[len(bin_data) : len(bin_data) * 2] = bin_data[: len(bin_data)]

    lines: list[str] = []
    if prefix_pad == 0:
        padded = bytes(image)
        for offset in range(0, len(padded), record_data_size):
            chunk = padded[offset : offset + record_data_size]
            if not chunk or all(value == 0xFF for value in chunk):
                continue
            lines.append(
                encode_srecord(
                    SRecord(
                        record_type="3",
                        count=0,
                        address=start_address + offset,
                        data=chunk,
                        checksum=0,
                        line_number=0,
                    )
                )
            )
        lines.append(encode_srecord(SRecord(record_type="7", count=0, address=0, data=b"", checksum=0, line_number=0)))
        return lines

    total_span = prefix_pad + len(image)
    record_count = (total_span + record_data_size - 1) // record_data_size
    for record_index in range(record_count):
        offset = record_index * record_data_size
        chunk = bytearray([0xFF] * record_data_size)
        logical_start = offset - prefix_pad
        src_start = max(logical_start, 0)
        src_end = min(logical_start + record_data_size, len(image))
        if src_start < src_end:
            dest_start = src_start - logical_start
            chunk[dest_start : dest_start + (src_end - src_start)] = image[src_start:src_end]
        if all(value == 0xFF for value in chunk):
            continue
        lines.append(
            encode_srecord(
                SRecord(
                    record_type="3",
                    count=0,
                    address=start_address + offset,
                    data=bytes(chunk),
                    checksum=0,
                    line_number=0,
                )
            )
        )
    lines.append(encode_srecord(SRecord(record_type="7", count=0, address=0, data=b"", checksum=0, line_number=0)))
    return lines


def build_fixed_60000000_hex_lines(segment_data: bytes) -> list[str]:
    if len(segment_data) != SEGMENT_BIN_SIZE:
        raise ValueError("BIN 文件长度必须是 16384 字节，才能按 60000000 规则输出 HEX。")

    lines: list[str] = []
    lines.append(
        encode_record(HexRecord(byte_count=2, address=0, record_type=4, data=bytes.fromhex("6000"), checksum=0, line_number=0))
    )
    for address in range(0, SEGMENT_BIN_SIZE, BYTES_PER_LINE):
        chunk = segment_data[address : address + BYTES_PER_LINE]
        lines.append(
            encode_record(HexRecord(byte_count=len(chunk), address=address, record_type=0, data=chunk, checksum=0, line_number=0))
        )

    lines.append(
        encode_record(HexRecord(byte_count=2, address=0, record_type=4, data=bytes.fromhex("6001"), checksum=0, line_number=0))
    )
    lines.append(
        encode_record(HexRecord(byte_count=2, address=0, record_type=4, data=bytes.fromhex("6002"), checksum=0, line_number=0))
    )
    for index, address in enumerate(range(0x8000, 0x8000 + SEGMENT_BIN_SIZE, BYTES_PER_LINE)):
        chunk = segment_data[index * BYTES_PER_LINE : (index + 1) * BYTES_PER_LINE]
        lines.append(
            encode_record(HexRecord(byte_count=len(chunk), address=address, record_type=0, data=chunk, checksum=0, line_number=0))
        )

    lines.append(encode_record(HexRecord(byte_count=0, address=0, record_type=1, data=b"", checksum=0, line_number=0)))
    return lines


def _build_a020_zero_page_starts(ext_value: int) -> list[int]:
    page = ext_value & 0xFF
    if 0x22 <= page <= 0x30:
        start = (0x32 - page) * 0x100
        return [start + index * 0x1100 for index in range(15)]
    if page == 0x31:
        return [0x0100 + index * 0x1100 for index in range(15)] + [0x0000]
    if 0x32 <= page <= 0x3E:
        start = (0x43 - page) * 0x100
        return [start + index * 0x1100 for index in range(15)]
    if page == 0x3F:
        return [0x0400 + index * 0x1100 for index in range(15)] + [0xFF00]
    return []


def build_a020_dual_group_hex_lines(bin_data: bytes | bytearray) -> list[str]:
    if len(bin_data) != DUAL_GROUP_SEGMENT_SIZE:
        raise ValueError("A020 两位总校验 BIN 长度必须是 65536 字节。")

    lines: list[str] = []
    for ext_value in range(A020_BASE_EXT, A020_BASE_EXT + 2):
        lines.append(
            encode_record(
                HexRecord(
                    byte_count=2,
                    address=0,
                    record_type=4,
                    data=ext_value.to_bytes(2, "big"),
                    checksum=0,
                    line_number=0,
                )
            )
        )
        for address in range(0, len(bin_data), BYTES_PER_LINE):
            chunk = bytes(bin_data[address : address + BYTES_PER_LINE])
            lines.append(
                encode_record(
                    HexRecord(
                        byte_count=len(chunk),
                        address=address,
                        record_type=0,
                        data=chunk,
                        checksum=0,
                        line_number=0,
                    )
                )
            )

    zero_chunk = bytes([0] * BYTES_PER_LINE)
    for ext_value in range(0xA022, 0xA040):
        lines.append(
            encode_record(
                HexRecord(
                    byte_count=2,
                    address=0,
                    record_type=4,
                    data=ext_value.to_bytes(2, "big"),
                    checksum=0,
                    line_number=0,
                )
            )
        )
        for page_start in _build_a020_zero_page_starts(ext_value):
            for address in range(page_start, page_start + 0x100, BYTES_PER_LINE):
                lines.append(
                    encode_record(
                        HexRecord(
                            byte_count=BYTES_PER_LINE,
                            address=address,
                            record_type=0,
                            data=zero_chunk,
                            checksum=0,
                            line_number=0,
                        )
                    )
                )
    return lines


class ParsedHexFile:
    def __init__(self, path: Path, records: list[HexRecord]) -> None:
        self.path = path
        self.mode_name = "HEX"
        self.family_label = "通用 Intel HEX"
        self.original_file_bytes = path.read_bytes()
        self.line_ending = b"\r\n" if b"\r\n" in self.original_file_bytes else b"\n"
        self.records = records
        self.memory: dict[int, int] = {}
        self.data_record_count = 0
        self.ext_record_count = 0
        self._load_memory()
        if not self.memory:
            raise ValueError("HEX 文件中没有数据记录。")

        self.data_addresses = sorted(self.memory)
        self.min_address = self.data_addresses[0]
        self.max_address = self.data_addresses[-1]
        self.full_size = self.max_address - self.min_address + 1
        self.present_offsets = {address - self.min_address for address in self.data_addresses}
        self.original_full_bin = self._build_full_bin()
        self.current_full_bin = bytearray(self.original_full_bin)
        self.segments = self._build_segments()
        self.checksum_scheme_name, self.checksum_regions = self._build_checksum_regions()
        self.family_label = self._detect_family_label()
        if self.path.name.lower() == "gps-3.hex" and self.min_address == 0x84000 and self.checksum_regions:
            self.checksum_scheme_name = "GPS 四字节总校验"
            for region in self.checksum_regions:
                region.scheme_name = self.checksum_scheme_name
        self.original_checksum_values = self.get_checksum_values(self.original_full_bin)

    @classmethod
    def from_path(cls, path: Path) -> "ParsedHexFile":
        return cls(path=path, records=parse_intel_hex(path))

    def _load_memory(self) -> None:
        current_ext = 0
        for record in self.records:
            if record.record_type == 2:
                if record.byte_count != 2:
                    raise ValueError(f"第 {record.line_number} 行扩展段地址长度错误。")
                current_ext = int.from_bytes(record.data, "big") << 4
                self.ext_record_count += 1
                continue
            if record.record_type == 4:
                if record.byte_count != 2:
                    raise ValueError(f"第 {record.line_number} 行扩展线性地址长度错误。")
                current_ext = int.from_bytes(record.data, "big") << 16
                self.ext_record_count += 1
                continue
            if record.record_type != 0:
                continue
            self.data_record_count += 1
            absolute = current_ext + record.address
            for index, value in enumerate(record.data):
                address = absolute + index
                if address in self.memory:
                    raise ValueError(f"发现重复地址: 0x{address:08X}")
                self.memory[address] = value

    def _build_full_bin(self) -> bytes:
        data = bytearray([0xFF] * self.full_size)
        for absolute_address, value in self.memory.items():
            data[absolute_address - self.min_address] = value
        return bytes(data)

    def _build_segments(self) -> list[tuple[int, int]]:
        segments: list[tuple[int, int]] = []
        start = self.data_addresses[0]
        previous = start
        for address in self.data_addresses[1:]:
            if address == previous + 1:
                previous = address
                continue
            segments.append((start, previous))
            start = address
            previous = address
        segments.append((start, previous))
        return segments

    def _find_full_blocks(self, block_size: int) -> list[tuple[int, int]]:
        blocks: list[tuple[int, int]] = []
        for start, end in self.segments:
            aligned_start = ((start + block_size - 1) // block_size) * block_size
            current = aligned_start
            while current + block_size - 1 <= end:
                blocks.append((current, current + block_size - 1))
                current += block_size
        return blocks

    def _build_checksum_regions(self) -> tuple[str, list[ChecksumRegion]]:
        dual_group_blocks = self._find_full_blocks(DUAL_GROUP_SEGMENT_SIZE)
        if dual_group_blocks:
            regions = [
                ChecksumRegion(
                    segment_index=index,
                    start_address=start,
                    end_address=end,
                    start_offset=start - self.min_address,
                    checksum_offset=start - self.min_address + DUAL_GROUP_CHECKSUM_OFFSET,
                    block_size=DUAL_GROUP_SEGMENT_SIZE,
                    checksum_size=2,
                    scheme_name="2字节总校验",
                )
                for index, (start, end) in enumerate(dual_group_blocks, start=1)
            ]
            return "2字节总校验", regions

        four_group_blocks = self._find_full_blocks(SEGMENT_BIN_SIZE)
        regions = [
            ChecksumRegion(
                segment_index=index,
                start_address=start,
                end_address=end,
                start_offset=start - self.min_address,
                checksum_offset=start - self.min_address + CHECKSUM_START_INDEX,
                block_size=SEGMENT_BIN_SIZE,
                checksum_size=4,
                scheme_name="4字节总校验",
            )
            for index, (start, end) in enumerate(four_group_blocks, start=1)
        ]
        if regions:
            return "4字节总校验", regions
        return "未自动识别", []

    def _detect_family_label(self) -> str:
        if self.path.name.lower() == "gps-3.hex" and self.min_address == 0x84000:
            return "GPS / 84000 / 带总校验"
        if self.checksum_scheme_name == "2字节总校验" and (self.min_address >> 16) == A020_BASE_EXT:
            return "A020 / 710"
        if self.checksum_scheme_name == "4字节总校验" and self.min_address == 0x60000000:
            return "60000000"
        return "通用 Intel HEX"

    @staticmethod
    def _calculate_segment_checksum(segment: bytes | bytearray) -> bytes:
        if len(segment) != SEGMENT_BIN_SIZE:
            raise ValueError("总校验算法要求段长度必须是 16384 字节。")
        sums = [0, 0, 0, 0]
        for index in range(CHECKSUM_START_INDEX):
            sums[index % 4] += segment[index]
        checksum_value = CHECKSUM_BASE
        checksum_value += (CHECKSUM_CONSTANTS[3] - sums[3]) << 24
        checksum_value += (CHECKSUM_CONSTANTS[2] - sums[2]) << 16
        checksum_value += (CHECKSUM_CONSTANTS[1] - sums[1]) << 8
        checksum_value += CHECKSUM_CONSTANTS[0] - sums[0]
        checksum_value %= 2**32
        return bytes(
            (
                checksum_value & 0xFF,
                (checksum_value >> 8) & 0xFF,
                (checksum_value >> 16) & 0xFF,
                (checksum_value >> 24) & 0xFF,
            )
        )

    def apply_checksum_rules(self, bin_data: bytearray) -> dict[int, bytes]:
        results: dict[int, bytes] = {}
        for region in self.checksum_regions:
            if region.checksum_size == 4:
                segment = bin_data[region.start_offset : region.start_offset + region.block_size]
                checksum_bytes = self._calculate_segment_checksum(segment)
            else:
                checksum_bytes = self._calculate_dual_group_checksum(region, bin_data)
            for index, value in enumerate(checksum_bytes):
                bin_data[region.checksum_offset + index] = value
            results[region.segment_index] = checksum_bytes
        return results

    def _calculate_dual_group_checksum(self, region: ChecksumRegion, bin_data: bytes | bytearray) -> bytes:
        segment = bin_data[region.start_offset : region.start_offset + region.block_size]
        checksum_value = 0
        for index in range(0, region.block_size - 2, 2):
            checksum_value += (segment[index] << 8) | segment[index + 1]
        checksum_value = (-checksum_value) & 0xFFFF
        return bytes(((checksum_value >> 8) & 0xFF, checksum_value & 0xFF))

    def get_checksum_values(self, bin_data: bytes | bytearray) -> dict[int, bytes]:
        values: dict[int, bytes] = {}
        for region in self.checksum_regions:
            values[region.segment_index] = bytes(
                bin_data[region.checksum_offset : region.checksum_offset + region.checksum_size]
            )
        return values

    def mirror_first_segment_to_second(self, bin_data: bytearray) -> bool:
        if len(self.checksum_regions) < 2:
            return False
        first_region = self.checksum_regions[0]
        second_region = self.checksum_regions[1]
        first_segment = bytes(bin_data[first_region.start_offset : first_region.start_offset + first_region.block_size])
        bin_data[second_region.start_offset : second_region.start_offset + second_region.block_size] = first_segment
        return True

    def build_output_lines(self, bin_data: bytes | bytearray) -> list[str]:
        output: list[str] = []
        current_ext = 0
        for record in self.records:
            if record.record_type == 2:
                current_ext = int.from_bytes(record.data, "big") << 4
                output.append(encode_record(record))
                continue
            if record.record_type == 4:
                current_ext = int.from_bytes(record.data, "big") << 16
                output.append(encode_record(record))
                continue
            if record.record_type != 0:
                output.append(encode_record(record))
                continue
            absolute_start = current_ext + record.address
            data = bytes(bin_data[absolute_start - self.min_address + index] for index in range(record.byte_count))
            output.append(encode_record(record, data_override=data))
        return output

    def build_output_bytes(self, bin_data: bytes | bytearray) -> bytes:
        if bytes(bin_data) == self.original_full_bin:
            return self.original_file_bytes
        lines = self.build_output_lines(bin_data)
        return self.line_ending.join(line.encode("ascii") for line in lines) + self.line_ending


class ParsedIntel80000File:
    def __init__(self, path: Path, records: list[HexRecord]) -> None:
        self.path = path
        self.mode_name = "HEX"
        self.family_label = "80000 / 704"
        self.original_file_bytes = path.read_bytes()
        self.line_ending = b"\r\n" if b"\r\n" in self.original_file_bytes else b"\n"
        self.records = records
        self.original_lines = [encode_record(record) for record in records]
        self.data_record_count = sum(1 for record in records if record.record_type == 0)
        self.ext_record_count = sum(1 for record in records if record.record_type == 2)
        self.min_address = INTEL_80000_BASE
        self.max_address = self.min_address + INTEL_80000_SEGMENT_SIZE - 1
        self.full_size = INTEL_80000_SEGMENT_SIZE
        self.present_offsets = set(range(self.full_size))
        self.data_addresses = list(range(self.min_address, self.max_address + 1))
        self.original_full_bin = self._build_compact_bin()
        self.current_full_bin = bytearray(self.original_full_bin)
        self.segments = [(self.min_address, self.max_address)]
        self.checksum_seed = derive_intel_80000_checksum_seed(self.original_full_bin)
        self.checksum_scheme_name = "80000两字节总校验"
        self.checksum_regions = [
            ChecksumRegion(
                segment_index=1,
                start_address=self.min_address,
                end_address=self.max_address,
                start_offset=0,
                checksum_offset=INTEL_80000_SEGMENT_SIZE - 2,
                block_size=INTEL_80000_SEGMENT_SIZE,
                checksum_size=2,
                scheme_name=self.checksum_scheme_name,
            )
        ]
        self.original_checksum_values = self.get_checksum_values(self.original_full_bin)

    def _build_compact_bin(self) -> bytes:
        first_half = bytearray([0xFF] * INTEL_80000_SEGMENT_SIZE)
        for record in self.records:
            if record.record_type != 0:
                continue
            if record.address >= INTEL_80000_SEGMENT_SIZE:
                continue
            first_half[record.address : record.address + record.byte_count] = record.data
        return bytes(first_half)

    def apply_checksum_rules(self, bin_data: bytearray) -> dict[int, bytes]:
        checksum_bytes = calculate_intel_80000_checksum(bin_data, seed=self.checksum_seed)
        region = self.checksum_regions[0]
        for index, value in enumerate(checksum_bytes):
            bin_data[region.checksum_offset + index] = value
        return {1: checksum_bytes}

    def get_checksum_values(self, bin_data: bytes | bytearray) -> dict[int, bytes]:
        region = self.checksum_regions[0]
        return {1: bytes(bin_data[region.checksum_offset : region.checksum_offset + region.checksum_size])}

    def mirror_first_segment_to_second(self, bin_data: bytearray) -> bool:
        return False

    def build_output_lines(self, bin_data: bytes | bytearray) -> list[str]:
        if bytes(bin_data) == self.original_full_bin:
            return list(self.original_lines)
        return build_intel_80000_hex_lines(bin_data)

    def build_output_bytes(self, bin_data: bytes | bytearray) -> bytes:
        if bytes(bin_data) == self.original_full_bin:
            return self.original_file_bytes
        lines = self.build_output_lines(bin_data)
        return self.line_ending.join(line.encode("ascii") for line in lines) + self.line_ending


class ParsedSrec200000File:
    def __init__(self, path: Path, records: list[SRecord]) -> None:
        self.path = path
        self.mode_name = "SREC"
        self.family_label = "200000 / 1161"
        self.original_file_bytes = path.read_bytes()
        self.line_ending = b"\r\n" if b"\r\n" in self.original_file_bytes else b"\n"
        self.records = records
        self.original_lines = [encode_srecord(record) for record in records]
        self.memory: dict[int, int] = {}
        self.data_record_count = 0
        self.ext_record_count = 0
        self._load_memory()
        self.bin_length = self._detect_bin_length()
        self.min_address = SREC_200000_BASE
        self.max_address = self.min_address + self.bin_length - 1
        self.display_base_address = SREC_200000_BASE
        self.display_size = 0x8000 if self.bin_length > SEGMENT_BIN_SIZE else self.bin_length
        self.full_size = self.bin_length
        self.present_offsets = set(range(self.full_size))
        self.data_addresses = list(range(self.min_address, self.max_address + 1))
        self.original_full_bin = self._build_compact_bin(self.min_address)
        self.current_full_bin = bytearray(self.original_full_bin)
        self.segments = [(self.min_address, self.max_address)]
        self.checksum_scheme_name = "200000四字节总校验"
        self.checksum_regions = [
            ChecksumRegion(
                segment_index=1,
                start_address=self.min_address,
                end_address=self.max_address,
                start_offset=0,
                checksum_offset=self.full_size - 4,
                block_size=self.full_size,
                checksum_size=4,
                scheme_name=self.checksum_scheme_name,
            )
        ]
        self.original_checksum_values = self.get_checksum_values(self.original_full_bin)

    @classmethod
    def from_path(cls, path: Path) -> "ParsedSrec200000File":
        return cls(path=path, records=parse_srecord(path))

    def _load_memory(self) -> None:
        for record in self.records:
            if record.record_type != "3":
                continue
            self.data_record_count += 1
            for index, value in enumerate(record.data):
                address = record.address + index
                if address in self.memory and self.memory[address] != value:
                    raise ValueError(f"发现重复地址且数据不一致: 0x{address:08X}")
                self.memory[address] = value

    def _detect_bin_length(self) -> int:
        first_non_ff_addresses = [
            address
            for address, value in self.memory.items()
            if SREC_200000_BASE <= address < SREC_200000_SECOND_BASE and value != 0xFF
        ]
        second_non_ff_addresses = [
            address for address, value in self.memory.items() if address >= SREC_200000_SECOND_BASE and value != 0xFF
        ]
        if not first_non_ff_addresses and not second_non_ff_addresses:
            raise ValueError("未发现 200000 规则的数据。")
        candidates: list[int] = []
        if first_non_ff_addresses:
            candidates.append(max(first_non_ff_addresses) - SREC_200000_BASE + 1)
        if second_non_ff_addresses:
            candidates.append(max(second_non_ff_addresses) - SREC_200000_SECOND_BASE + 1)
        bin_length = max(candidates)
        if bin_length < 4 or bin_length > SREC_200000_MIRROR_OFFSET:
            raise ValueError("200000 规则数据长度超出预期范围。")
        return bin_length

    def _build_compact_bin(self, base_address: int) -> bytes:
        data = bytearray([0xFF] * self.bin_length)
        for offset in range(self.bin_length):
            data[offset] = self.memory.get(base_address + offset, 0xFF)
        return bytes(data)

    def apply_checksum_rules(self, bin_data: bytearray) -> dict[int, bytes]:
        checksum_bytes = calculate_200000_checksum(bin_data)
        region = self.checksum_regions[0]
        for index, value in enumerate(checksum_bytes):
            bin_data[region.checksum_offset + index] = value
        return {1: checksum_bytes}

    def get_checksum_values(self, bin_data: bytes | bytearray) -> dict[int, bytes]:
        region = self.checksum_regions[0]
        return {1: bytes(bin_data[region.checksum_offset : region.checksum_offset + region.checksum_size])}

    def mirror_first_segment_to_second(self, bin_data: bytearray) -> bool:
        return False

    def build_output_lines(self, bin_data: bytes | bytearray) -> list[str]:
        if bytes(bin_data) == self.original_full_bin:
            return list(self.original_lines)

        image = bytearray([0xFF] * SREC_200000_TOTAL_IMAGE_SIZE)
        image[: self.bin_length] = bin_data[: self.bin_length]
        second_start = SREC_200000_MIRROR_OFFSET
        image[second_start : second_start + self.bin_length] = bin_data[: self.bin_length]

        output: list[str] = []
        for offset in range(0, len(image), SREC_200000_RECORD_DATA_SIZE):
            chunk = bytes(image[offset : offset + SREC_200000_RECORD_DATA_SIZE])
            if not chunk or all(value == 0xFF for value in chunk):
                continue
            output.append(
                encode_srecord(
                    SRecord(
                        record_type="3",
                        count=0,
                        address=SREC_200000_BASE + offset,
                        data=chunk,
                        checksum=0,
                        line_number=0,
                    )
                )
            )
        output.append(encode_srecord(SRecord(record_type="7", count=0, address=0, data=b"", checksum=0, line_number=0)))
        return output

    def build_output_bytes(self, bin_data: bytes | bytearray) -> bytes:
        if bytes(bin_data) == self.original_full_bin:
            return self.original_file_bytes
        lines = self.build_output_lines(bin_data)
        return self.line_ending.join(line.encode("ascii") for line in lines) + self.line_ending


class ParsedSrec800000File:
    def __init__(self, path: Path, records: list[SRecord]) -> None:
        self.path = path
        self.mode_name = "SREC"
        self.family_label = "800000 / 1013"
        self.original_file_bytes = path.read_bytes()
        self.line_ending = b"\r\n" if b"\r\n" in self.original_file_bytes else b"\n"
        self.records = records
        self.original_lines = [encode_srecord(record) for record in records]
        self.memory: dict[int, int] = {}
        self.data_record_count = 0
        self.ext_record_count = 0
        self._load_memory()
        self.bin_length = self._detect_bin_length()
        self.min_address = SREC_800000_BASE
        self.max_address = self.min_address + self.bin_length - 1
        self.full_size = self.bin_length
        self.present_offsets = set(range(self.full_size))
        self.data_addresses = list(range(self.min_address, self.max_address + 1))
        self.original_full_bin = self._build_compact_bin(self.min_address)
        self.current_full_bin = bytearray(self.original_full_bin)
        self.segments = [(self.min_address, self.max_address)]
        self.checksum_scheme_name = "800000四字节总校验"
        self.checksum_regions = [
            ChecksumRegion(
                segment_index=1,
                start_address=self.min_address,
                end_address=self.max_address,
                start_offset=0,
                checksum_offset=self.full_size - 4,
                block_size=self.full_size,
                checksum_size=4,
                scheme_name=self.checksum_scheme_name,
            )
        ]
        self.original_checksum_values = self.get_checksum_values(self.original_full_bin)

    def _load_memory(self) -> None:
        for record in self.records:
            if record.record_type != "3":
                continue
            self.data_record_count += 1
            for index, value in enumerate(record.data):
                address = record.address + index
                if address in self.memory and self.memory[address] != value:
                    raise ValueError(f"发现重复地址且数据不一致: 0x{address:08X}")
                self.memory[address] = value

    def _detect_bin_length(self) -> int:
        first_non_ff_addresses = [
            address
            for address, value in self.memory.items()
            if SREC_800000_BASE <= address < SREC_800000_SECOND_BASE and value != 0xFF
        ]
        second_non_ff_addresses = [
            address for address, value in self.memory.items() if address >= SREC_800000_SECOND_BASE and value != 0xFF
        ]
        if not first_non_ff_addresses and not second_non_ff_addresses:
            raise ValueError("未发现 800000 规则的数据。")
        candidates: list[int] = []
        if first_non_ff_addresses:
            candidates.append(max(first_non_ff_addresses) - SREC_800000_BASE + 1)
        if second_non_ff_addresses:
            candidates.append(max(second_non_ff_addresses) - SREC_800000_SECOND_BASE + 1)
        bin_length = max(candidates)
        if bin_length < 4 or bin_length > SREC_800000_MIRROR_OFFSET:
            raise ValueError("800000 规则数据长度超出预期范围。")
        return bin_length

    def _build_compact_bin(self, base_address: int) -> bytes:
        data = bytearray([0xFF] * self.bin_length)
        for offset in range(self.bin_length):
            data[offset] = self.memory.get(base_address + offset, 0xFF)
        return bytes(data)

    def apply_checksum_rules(self, bin_data: bytearray) -> dict[int, bytes]:
        checksum_bytes = calculate_200000_checksum(bin_data)
        region = self.checksum_regions[0]
        for index, value in enumerate(checksum_bytes):
            bin_data[region.checksum_offset + index] = value
        return {1: checksum_bytes}

    def get_checksum_values(self, bin_data: bytes | bytearray) -> dict[int, bytes]:
        region = self.checksum_regions[0]
        return {1: bytes(bin_data[region.checksum_offset : region.checksum_offset + region.checksum_size])}

    def mirror_first_segment_to_second(self, bin_data: bytearray) -> bool:
        return False

    def build_output_lines(self, bin_data: bytes | bytearray) -> list[str]:
        if bytes(bin_data) == self.original_full_bin:
            return list(self.original_lines)
        return build_800000_family_lines(bin_data)

    def build_output_bytes(self, bin_data: bytes | bytearray) -> bytes:
        if bytes(bin_data) == self.original_full_bin:
            return self.original_file_bytes
        lines = self.build_output_lines(bin_data)
        return self.line_ending.join(line.encode("ascii") for line in lines) + self.line_ending


class ParsedSrec400000File:
    def __init__(
        self,
        path: Path,
        records: list[SRecord],
        *,
        original_lines: list[str] | None = None,
        output_record_data_size: int = SREC_400000_SOURCE_RECORD_DATA_SIZE,
        output_checksum_mode: str = "400000_s3fd",
    ) -> None:
        self.path = path
        self.mode_name = "SREC"
        self.family_label = "400000 / S3FD / 1050 / 778"
        self.records = records
        self.output_record_data_size = output_record_data_size
        self.output_checksum_mode = output_checksum_mode
        self.original_file_bytes = path.read_bytes()
        self.line_ending = b"\r\n" if b"\r\n" in self.original_file_bytes else b"\n"
        self.terminator_prefix, self.terminator_suffix = self._extract_terminator_wrapping()
        self.original_lines = (
            list(original_lines)
            if original_lines is not None
            else [encode_srecord(record, checksum_mode=output_checksum_mode) for record in records]
        )
        self.memory: dict[int, int] = {}
        self.data_record_count = 0
        self.ext_record_count = 0
        self._load_memory()
        self.min_address = SREC_400000_BASE
        self.max_address = self.min_address + SREC_400000_BIN_SIZE - 1
        self.full_size = SREC_400000_BIN_SIZE
        self.present_offsets = set(range(self.full_size))
        self.data_addresses = list(range(self.min_address, self.max_address + 1))
        self.original_full_bin = self._build_compact_bin()
        self.current_full_bin = bytearray(self.original_full_bin)
        self.segments = [(self.min_address, self.max_address)]
        self.checksum_scheme_name = "400000四字节总校验"
        self.checksum_regions = [
            ChecksumRegion(
                segment_index=1,
                start_address=self.min_address,
                end_address=self.max_address,
                start_offset=0,
                checksum_offset=CHECKSUM_START_INDEX,
                block_size=self.full_size,
                checksum_size=4,
                scheme_name=self.checksum_scheme_name,
            )
        ]
        self.original_checksum_values = self.get_checksum_values(self.original_full_bin)

    def _extract_terminator_wrapping(self) -> tuple[bytes, bytes]:
        for raw_line in self.original_file_bytes.splitlines():
            marker = raw_line.find(b"S")
            if marker < 0:
                continue
            tail = raw_line[marker:]
            if not tail.startswith(b"S70500000000FA"):
                continue
            return raw_line[:marker], raw_line[marker + len(b"S70500000000FA") :]
        return b"", b""

    def _load_memory(self) -> None:
        for record in self.records:
            if record.record_type != "3":
                continue
            self.data_record_count += 1
            for index, value in enumerate(record.data):
                address = record.address + index
                if address in self.memory and self.memory[address] != value:
                    raise ValueError(f"发现重复地址且数据不一致: 0x{address:08X}")
                self.memory[address] = value

    def _build_compact_bin(self) -> bytes:
        data = bytearray([0xFF] * self.full_size)
        for offset in range(self.full_size):
            data[offset] = self.memory.get(self.min_address + offset, 0xFF)
        return bytes(data)

    def apply_checksum_rules(self, bin_data: bytearray) -> dict[int, bytes]:
        checksum_bytes = calculate_200000_checksum(bin_data)
        region = self.checksum_regions[0]
        for index, value in enumerate(checksum_bytes):
            bin_data[region.checksum_offset + index] = value
        return {1: checksum_bytes}

    def get_checksum_values(self, bin_data: bytes | bytearray) -> dict[int, bytes]:
        region = self.checksum_regions[0]
        return {1: bytes(bin_data[region.checksum_offset : region.checksum_offset + region.checksum_size])}

    def mirror_first_segment_to_second(self, bin_data: bytearray) -> bool:
        return False

    def build_output_lines(self, bin_data: bytes | bytearray) -> list[str]:
        if bytes(bin_data) == self.original_full_bin:
            return list(self.original_lines)
        return build_400000_family_lines(
            bin_data,
            record_data_size=self.output_record_data_size,
            checksum_mode=self.output_checksum_mode,
        )

    def build_output_bytes(self, bin_data: bytes | bytearray) -> bytes:
        if bytes(bin_data) == self.original_full_bin:
            return self.original_file_bytes

        lines = self.build_output_lines(bin_data)
        encoded_lines = [line.encode("ascii") for line in lines[:-1]]
        encoded_lines.append(self.terminator_prefix + lines[-1].encode("ascii") + self.terminator_suffix)
        return self.line_ending.join(encoded_lines) + self.line_ending


class ParsedSrec14080000File:
    def __init__(self, path: Path, records: list[SRecord]) -> None:
        self.path = path
        self.mode_name = "SREC"
        self.family_label = "14080000 / 1001"
        self.original_file_bytes = path.read_bytes()
        self.line_ending = b"\r\n" if b"\r\n" in self.original_file_bytes else b"\n"
        self.records = records
        self.original_lines = [encode_srecord(record) for record in records]
        self.memory: dict[int, int] = {}
        self.data_record_count = 0
        self.ext_record_count = 0
        self._load_memory()
        self.min_address = SREC_14080000_BASE
        self.max_address = self.min_address + DUAL_GROUP_SEGMENT_SIZE - 1
        self.full_size = DUAL_GROUP_SEGMENT_SIZE
        self.present_offsets = set(range(self.full_size))
        self.data_addresses = list(range(self.min_address, self.max_address + 1))
        self.original_full_bin = self._build_compact_bin()
        self.current_full_bin = bytearray(self.original_full_bin)
        self.segments = [(self.min_address, self.max_address)]
        self.checksum_scheme_name = "14080000两字节总校验"
        self.checksum_regions = [
            ChecksumRegion(
                segment_index=1,
                start_address=self.min_address,
                end_address=self.max_address,
                start_offset=0,
                checksum_offset=DUAL_GROUP_CHECKSUM_OFFSET,
                block_size=DUAL_GROUP_SEGMENT_SIZE,
                checksum_size=2,
                scheme_name=self.checksum_scheme_name,
            )
        ]
        self.original_checksum_values = self.get_checksum_values(self.original_full_bin)

    @classmethod
    def from_path(cls, path: Path) -> "ParsedSrec14080000File":
        return cls(path=path, records=parse_srecord(path))

    def _load_memory(self) -> None:
        for record in self.records:
            if record.record_type != "3":
                continue
            self.data_record_count += 1
            for index, value in enumerate(record.data):
                address = record.address + index
                if address in self.memory and self.memory[address] != value:
                    raise ValueError(f"发现重复地址且数据不一致: 0x{address:08X}")
                self.memory[address] = value

    def _build_compact_bin(self) -> bytes:
        data = bytearray([0xFF] * self.full_size)
        for offset in range(self.full_size):
            data[offset] = self.memory.get(self.min_address + offset, 0xFF)
        return bytes(data)

    def apply_checksum_rules(self, bin_data: bytearray) -> dict[int, bytes]:
        checksum_value = 0
        for index in range(0, self.full_size - 2, 2):
            checksum_value += (bin_data[index] << 8) | bin_data[index + 1]
        checksum_value = (-checksum_value) & 0xFFFF
        checksum_bytes = bytes(((checksum_value >> 8) & 0xFF, checksum_value & 0xFF))
        region = self.checksum_regions[0]
        for index, value in enumerate(checksum_bytes):
            bin_data[region.checksum_offset + index] = value
        return {1: checksum_bytes}

    def get_checksum_values(self, bin_data: bytes | bytearray) -> dict[int, bytes]:
        region = self.checksum_regions[0]
        return {1: bytes(bin_data[region.checksum_offset : region.checksum_offset + region.checksum_size])}

    def mirror_first_segment_to_second(self, bin_data: bytearray) -> bool:
        return False

    def build_output_lines(self, bin_data: bytes | bytearray) -> list[str]:
        if bytes(bin_data) == self.original_full_bin:
            return list(self.original_lines)
        return build_shifted_mirrored_s3_lines(
            bin_data,
            start_address=SREC_14080000_START,
            prefix_pad=SREC_14080000_PREFIX_PAD,
            record_data_size=SREC_14080000_RECORD_DATA_SIZE,
        )

    def build_output_bytes(self, bin_data: bytes | bytearray) -> bytes:
        if bytes(bin_data) == self.original_full_bin:
            return self.original_file_bytes
        lines = self.build_output_lines(bin_data)
        return self.line_ending.join(line.encode("ascii") for line in lines) + self.line_ending


class ParsedSrecFile:
    def __init__(self, path: Path, records: list[SRecord]) -> None:
        self.path = path
        self.mode_name = "SREC"
        self.family_label = "通用 S-Record"
        self.original_file_bytes = path.read_bytes()
        self.line_ending = b"\r\n" if b"\r\n" in self.original_file_bytes else b"\n"
        self.records = records
        self.memory: dict[int, int] = {}
        self.data_record_count = 0
        self.ext_record_count = 0
        self._load_memory()
        if not self.memory:
            raise ValueError("S Record 文件中没有数据记录。")

        self.data_addresses = sorted(self.memory)
        self.min_address = self.data_addresses[0]
        self.max_address = self.data_addresses[-1]
        self.full_size = self.max_address - self.min_address + 1
        self.present_offsets = {address - self.min_address for address in self.data_addresses}
        self.original_full_bin = self._build_full_bin()
        self.current_full_bin = bytearray(self.original_full_bin)
        self.segments = self._build_segments()
        self.checksum_scheme_name, self.checksum_regions = self._build_checksum_regions()
        self.original_checksum_values = self.get_checksum_values(self.original_full_bin)

    @classmethod
    def from_path(cls, path: Path) -> "ParsedSrecFile":
        return cls(path=path, records=parse_srecord(path))

    def _load_memory(self) -> None:
        for record in self.records:
            if record.record_type not in {"1", "2", "3"}:
                continue
            self.data_record_count += 1
            for index, value in enumerate(record.data):
                address = record.address + index
                if address in self.memory:
                    raise ValueError(f"发现重复地址: 0x{address:08X}")
                self.memory[address] = value

    def _build_full_bin(self) -> bytes:
        data = bytearray([0xFF] * self.full_size)
        for absolute_address, value in self.memory.items():
            data[absolute_address - self.min_address] = value
        return bytes(data)

    def _build_segments(self) -> list[tuple[int, int]]:
        segments: list[tuple[int, int]] = []
        start = self.data_addresses[0]
        previous = start
        for address in self.data_addresses[1:]:
            if address == previous + 1:
                previous = address
                continue
            segments.append((start, previous))
            start = address
            previous = address
        segments.append((start, previous))
        return segments

    def _find_full_blocks(self, block_size: int) -> list[tuple[int, int]]:
        blocks: list[tuple[int, int]] = []
        for start, end in self.segments:
            aligned_start = ((start + block_size - 1) // block_size) * block_size
            current = aligned_start
            while current + block_size - 1 <= end:
                blocks.append((current, current + block_size - 1))
                current += block_size
        return blocks

    def _build_checksum_regions(self) -> tuple[str, list[ChecksumRegion]]:
        dual_group_blocks = self._find_full_blocks(DUAL_GROUP_SEGMENT_SIZE)
        if dual_group_blocks:
            regions = [
                ChecksumRegion(
                    segment_index=index,
                    start_address=start,
                    end_address=end,
                    start_offset=start - self.min_address,
                    checksum_offset=start - self.min_address + DUAL_GROUP_CHECKSUM_OFFSET,
                    block_size=DUAL_GROUP_SEGMENT_SIZE,
                    checksum_size=2,
                    scheme_name="2字节总校验",
                )
                for index, (start, end) in enumerate(dual_group_blocks, start=1)
            ]
            return "2字节总校验", regions

        four_group_blocks = self._find_full_blocks(SEGMENT_BIN_SIZE)
        regions = [
            ChecksumRegion(
                segment_index=index,
                start_address=start,
                end_address=end,
                start_offset=start - self.min_address,
                checksum_offset=start - self.min_address + CHECKSUM_START_INDEX,
                block_size=SEGMENT_BIN_SIZE,
                checksum_size=4,
                scheme_name="4字节总校验",
            )
            for index, (start, end) in enumerate(four_group_blocks, start=1)
        ]
        if regions:
            return "4字节总校验", regions
        return "未自动识别", []

    def apply_checksum_rules(self, bin_data: bytearray) -> dict[int, bytes]:
        results: dict[int, bytes] = {}
        for region in self.checksum_regions:
            if region.checksum_size == 4:
                segment = bin_data[region.start_offset : region.start_offset + region.block_size]
                checksum_bytes = ParsedHexFile._calculate_segment_checksum(segment)
            else:
                checksum_bytes = self._calculate_dual_group_checksum(region, bin_data)
            for index, value in enumerate(checksum_bytes):
                bin_data[region.checksum_offset + index] = value
            results[region.segment_index] = checksum_bytes
        return results

    def _calculate_dual_group_checksum(self, region: ChecksumRegion, bin_data: bytes | bytearray) -> bytes:
        segment = bin_data[region.start_offset : region.start_offset + region.block_size]
        checksum_value = 0
        for index in range(0, region.block_size - 2, 2):
            checksum_value += (segment[index] << 8) | segment[index + 1]
        checksum_value = (-checksum_value) & 0xFFFF
        return bytes(((checksum_value >> 8) & 0xFF, checksum_value & 0xFF))

    def get_checksum_values(self, bin_data: bytes | bytearray) -> dict[int, bytes]:
        values: dict[int, bytes] = {}
        for region in self.checksum_regions:
            values[region.segment_index] = bytes(
                bin_data[region.checksum_offset : region.checksum_offset + region.checksum_size]
            )
        return values

    def mirror_first_segment_to_second(self, bin_data: bytearray) -> bool:
        if len(self.checksum_regions) < 2:
            return False
        first_region = self.checksum_regions[0]
        second_region = self.checksum_regions[1]
        first_segment = bytes(bin_data[first_region.start_offset : first_region.start_offset + first_region.block_size])
        bin_data[second_region.start_offset : second_region.start_offset + second_region.block_size] = first_segment
        return True

    def build_output_lines(self, bin_data: bytes | bytearray) -> list[str]:
        output: list[str] = []
        for record in self.records:
            if record.record_type not in {"1", "2", "3"}:
                output.append(encode_srecord(record))
                continue
            data = bytes(bin_data[record.address - self.min_address + index] for index in range(len(record.data)))
            output.append(encode_srecord(record, data_override=data))
        return output

    def build_output_bytes(self, bin_data: bytes | bytearray) -> bytes:
        if bytes(bin_data) == self.original_full_bin:
            return self.original_file_bytes
        lines = self.build_output_lines(bin_data)
        return self.line_ending.join(line.encode("ascii") for line in lines) + self.line_ending


class ParsedBinFile:
    def __init__(self, path: Path, data: bytes) -> None:
        if len(data) not in {SEGMENT_BIN_SIZE, DUAL_GROUP_SEGMENT_SIZE}:
            raise ValueError("BIN 文件长度目前只支持 16384 或 65536 字节。")

        self.path = path
        self.mode_name = "BIN"
        self.records: list[HexRecord] = []
        self.data_record_count = 0
        self.ext_record_count = 0
        self.min_address = 0
        self.max_address = len(data) - 1
        self.full_size = len(data)
        self.present_offsets = set(range(len(data)))
        self.data_addresses = list(range(len(data)))
        self.original_full_bin = bytes(data)
        self.current_full_bin = bytearray(data)
        self.segments = [(0, len(data) - 1)]
        if len(data) == DUAL_GROUP_SEGMENT_SIZE:
            self.checksum_scheme_name = "2字节总校验"
            checksum_offset = DUAL_GROUP_CHECKSUM_OFFSET
            checksum_size = 2
        else:
            self.checksum_scheme_name = "4字节总校验"
            checksum_offset = CHECKSUM_START_INDEX
            checksum_size = 4
        self.checksum_regions = [
            ChecksumRegion(
                segment_index=1,
                start_address=0,
                end_address=len(data) - 1,
                start_offset=0,
                checksum_offset=checksum_offset,
                block_size=len(data),
                checksum_size=checksum_size,
                scheme_name=self.checksum_scheme_name,
            )
        ]
        self.original_checksum_values = self.get_checksum_values(self.original_full_bin)

    @classmethod
    def from_path(cls, path: Path) -> "ParsedBinFile":
        return cls(path=path, data=path.read_bytes())

    def apply_checksum_rules(self, bin_data: bytearray) -> dict[int, bytes]:
        region = self.checksum_regions[0]
        if region.checksum_size == 4:
            checksum_bytes = ParsedHexFile._calculate_segment_checksum(bin_data)
        else:
            checksum_bytes = self._calculate_dual_group_checksum(bin_data)
        for index, value in enumerate(checksum_bytes):
            bin_data[region.checksum_offset + index] = value
        return {1: checksum_bytes}

    def get_checksum_values(self, bin_data: bytes | bytearray) -> dict[int, bytes]:
        region = self.checksum_regions[0]
        return {1: bytes(bin_data[region.checksum_offset : region.checksum_offset + region.checksum_size])}

    def _calculate_dual_group_checksum(self, bin_data: bytes | bytearray) -> bytes:
        checksum_value = 0
        for index in range(0, DUAL_GROUP_SEGMENT_SIZE - 2, 2):
            checksum_value += (bin_data[index] << 8) | bin_data[index + 1]
        checksum_value = (-checksum_value) & 0xFFFF
        return bytes(((checksum_value >> 8) & 0xFF, checksum_value & 0xFF))

    def mirror_first_segment_to_second(self, bin_data: bytearray) -> bool:
        return False

    def build_output_lines(self, bin_data: bytes | bytearray) -> list[str]:
        if self.checksum_regions[0].checksum_size == 4:
            return build_fixed_60000000_hex_lines(bytes(bin_data))
        lines: list[str] = []
        for address in range(0, len(bin_data), BYTES_PER_LINE):
            chunk = bytes(bin_data[address : address + BYTES_PER_LINE])
            lines.append(
                encode_record(HexRecord(byte_count=len(chunk), address=address, record_type=0, data=chunk, checksum=0, line_number=0))
            )
        lines.append(encode_record(HexRecord(byte_count=0, address=0, record_type=1, data=b"", checksum=0, line_number=0)))
        return lines


class ParsedBinFile:
    def __init__(self, path: Path, data: bytes) -> None:
        if len(data) < 4:
            raise ValueError("BIN 文件长度太小，无法识别校验类型。")

        self.path = path
        self.mode_name = "BIN"
        self.records: list[HexRecord] = []
        self.data_record_count = 0
        self.ext_record_count = 0
        self.family_code = self._read_family_code(data)
        self.family_name = self._detect_family(data)
        self.family_label = self._build_family_label()
        compact_data = self._normalize_bin_payload(data)
        self.is_1161_second_gen = False

        if self.family_name == "a020_dual_group":
            self.min_address = A020_BASE_EXT << 16
            self.checksum_scheme_name = "2字节总校验"
            checksum_offset = DUAL_GROUP_CHECKSUM_OFFSET
            checksum_size = 2
        elif self.family_name in {"intel_80000", "intel_80000_full"}:
            self.min_address = INTEL_80000_BASE
            self.checksum_scheme_name = "80000两字节总校验"
            checksum_offset = INTEL_80000_SEGMENT_SIZE - 2
            checksum_size = 2
            self.checksum_seed = derive_intel_80000_checksum_seed(compact_data)
        elif self.family_name in {"srec_400000", "srec_400000_full"}:
            self.min_address = SREC_400000_BASE
            self.checksum_scheme_name = "400000四字节总校验"
            checksum_offset = CHECKSUM_START_INDEX
            checksum_size = 4
        elif self.family_name in {"srec_14080000", "srec_14080000_full"}:
            self.min_address = SREC_14080000_BASE
            self.checksum_scheme_name = "14080000两字节总校验"
            checksum_offset = DUAL_GROUP_CHECKSUM_OFFSET
            checksum_size = 2
        elif self.family_name in {"srec_800000", "srec_800000_full"}:
            self.min_address = SREC_800000_BASE
            self.checksum_scheme_name = "800000四字节总校验"
            checksum_offset = len(compact_data) - 4
            checksum_size = 4
        elif self.family_name in {"srec_200000", "srec_200000_full"}:
            self.min_address = SREC_200000_BASE
            self.checksum_scheme_name = "200000四字节总校验"
            checksum_offset = len(compact_data) - 4
            checksum_size = 4
            self.is_1161_second_gen = (
                self.family_code == 0x04
                or len(compact_data) > SEGMENT_BIN_SIZE
                or "二代" in self.path.name
                or "2代" in self.path.name
            )
        else:
            if len(compact_data) != SEGMENT_BIN_SIZE:
                raise ValueError("60000000 四位校验 BIN 长度必须是 16384 字节。")
            self.min_address = 0x60000000
            self.checksum_scheme_name = "4字节总校验"
            checksum_offset = CHECKSUM_START_INDEX
            checksum_size = 4

        self.max_address = self.min_address + len(compact_data) - 1
        self.display_base_address = self.min_address
        if self.family_name in {"srec_200000", "srec_200000_full"} and self.is_1161_second_gen:
            self.display_size = len(compact_data) + 1
        else:
            self.display_size = len(compact_data)
        self.full_size = len(compact_data)
        self.present_offsets = set(range(len(compact_data)))
        self.data_addresses = list(range(self.min_address, self.max_address + 1))
        self.original_full_bin = bytes(compact_data)
        self.current_full_bin = bytearray(compact_data)
        self.segments = [(self.min_address, self.max_address)]
        self.checksum_regions = [
            ChecksumRegion(
                segment_index=1,
                start_address=self.min_address,
                end_address=self.max_address,
                start_offset=0,
                checksum_offset=checksum_offset,
                block_size=len(compact_data),
                checksum_size=checksum_size,
                scheme_name=self.checksum_scheme_name,
            )
        ]
        self.original_checksum_values = self.get_checksum_values(self.original_full_bin)

    @classmethod
    def from_path(cls, path: Path) -> "ParsedBinFile":
        return cls(path=path, data=path.read_bytes())

    def _name_has_any(self, *patterns: str) -> bool:
        lowered_name = self.path.name.lower()
        return any(pattern in lowered_name for pattern in patterns)

    def _read_family_code(self, data: bytes) -> int | None:
        if len(data) <= BIN_FAMILY_CODE_OFFSET:
            return None
        code = data[BIN_FAMILY_CODE_OFFSET]
        return code if code in BIN_FAMILY_CODE_MAP else None

    def _family_from_code(self, data: bytes) -> str | None:
        if self.family_code is None:
            return None
        family_key = BIN_FAMILY_CODE_MAP[self.family_code]
        if family_key == "778_one":
            return "srec_400000_full" if len(data) > SEGMENT_BIN_SIZE else "srec_400000"
        if family_key == "60000000":
            return "intel_60000000"
        if family_key in {"1161_one", "1161_two"}:
            return "srec_200000_full" if len(data) > SREC_200000_MIRROR_OFFSET else "srec_200000"
        if family_key in {"1001_one", "1001_two"}:
            return "srec_14080000_full" if len(data) > DUAL_GROUP_SEGMENT_SIZE else "srec_14080000"
        if family_key == "704":
            return "intel_80000_full" if len(data) > INTEL_80000_SEGMENT_SIZE else "intel_80000"
        if family_key == "800000":
            return "srec_800000_full" if len(data) > SREC_800000_MIRROR_OFFSET else "srec_800000"
        if family_key == "710":
            return "a020_dual_group"
        return None

    def _build_family_label(self) -> str:
        if self.family_code is not None:
            labels_by_code = {
                0x01: "778",
                0x02: "60000000",
                0x03: "1161 一代",
                0x04: "1161 二代",
                0x05: "1001 一代",
                0x06: "1001 二代",
                0x07: "704",
                0x08: "800000 / 1013",
                0x09: "710",
            }
            base_label = labels_by_code.get(self.family_code)
            if base_label is not None:
                return f"{base_label} / 编码识别"
        if self.family_name in {"srec_200000", "srec_200000_full"}:
            if "二代" in self.path.name or "2代" in self.path.name:
                return "200000 / 1161 二代"
            if "一代" in self.path.name or "1代" in self.path.name:
                return "200000 / 1161 一代"
        labels = {
            "a020_dual_group": "A020 / 710",
            "intel_80000": "80000 / 704",
            "intel_80000_full": "80000 / 704 整镜像BIN",
            "srec_400000": "400000 / S3FD / 1050 / 778",
            "srec_400000_full": "400000 / S3FD / 1050 / 778 整镜像BIN",
            "srec_14080000": "14080000 / 1001",
            "srec_14080000_full": "14080000 / 1001 整镜像BIN",
            "srec_200000": "200000 / 1161",
            "srec_200000_full": "200000 / 1161 整镜像BIN",
            "srec_800000": "800000 / 1013",
            "srec_800000_full": "800000 / 1013 整镜像BIN",
            "intel_60000000": "60000000",
        }
        return labels.get(self.family_name, self.family_name)

    def _detect_family(self, data: bytes) -> str:
        coded_family = self._family_from_code(data)
        if coded_family is not None:
            return coded_family

        if self._name_has_any("1013", "800000") and len(data) > SREC_800000_MIRROR_OFFSET:
            return "srec_800000_full"
        if self._name_has_any("1013", "800000") and len(data) > SEGMENT_BIN_SIZE:
            return "srec_800000"
        if self._name_has_any("710", "a020") and len(data) == DUAL_GROUP_SEGMENT_SIZE:
            return "a020_dual_group"
        if self._name_has_any("kcc", "1001", "1408") and len(data) > DUAL_GROUP_SEGMENT_SIZE:
            return "srec_14080000_full"
        if self._name_has_any("778", "1050", "400000") and len(data) > SEGMENT_BIN_SIZE:
            return "srec_400000_full"
        if self._name_has_any("1161", "200000") and len(data) > SREC_200000_MIRROR_OFFSET:
            return "srec_200000_full"
        if self._name_has_any("704", "80000") and len(data) > INTEL_80000_SEGMENT_SIZE:
            return "intel_80000_full"

        if len(data) == SREC_14080000_IMAGE_SIZE:
            return "srec_14080000_full"
        if len(data) == SREC_400000_IMAGE_SIZE:
            return "srec_400000_full"
        if len(data) == SREC_200000_TOTAL_IMAGE_SIZE:
            return "srec_200000_full"
        if len(data) == INTEL_80000_SEGMENT_SIZE:
            return "intel_80000"
        if len(data) == SREC_800000_MIRROR_OFFSET:
            return "srec_800000"
        if len(data) == INTEL_80000_TOTAL_SIZE and self._name_has_any("704", "80000"):
            return "intel_80000_full"
        if len(data) == DUAL_GROUP_SEGMENT_SIZE:
            first_half = data[:SREC_800000_MIRROR_OFFSET]
            second_half = data[SREC_800000_MIRROR_OFFSET : SREC_800000_TOTAL_IMAGE_SIZE]
            if first_half == second_half:
                first_non_ff = [index for index, value in enumerate(first_half) if value != 0xFF]
                compact_length = max(first_non_ff) + 1 if first_non_ff else 0
                compact_length = max(4, compact_length)
                candidate = bytes(first_half[:compact_length])
                if len(candidate) >= 4 and candidate[-4:] == calculate_200000_checksum(candidate):
                    return "srec_800000_full"
                return "intel_80000_full"
            if self._name_has_any("kcc", "1001", "1408"):
                return "srec_14080000"
            return "a020_dual_group"
        if len(data) != SEGMENT_BIN_SIZE:
            return "srec_200000"

        if self._name_has_any("778", "1050", "400000"):
            return "srec_400000"

        old_checksum = ParsedHexFile._calculate_segment_checksum(data)
        family_200000_checksum = calculate_200000_checksum(data)
        tail = data[-4:]
        if tail == old_checksum and tail != family_200000_checksum:
            return "intel_60000000"
        if tail == family_200000_checksum and tail != old_checksum:
            if self._name_has_any("1161", "200000"):
                return "srec_200000"
            return "srec_400000"

        if self._name_has_any("1161", "200000"):
            return "srec_200000"
        return "intel_60000000"

    def _normalize_bin_payload(self, data: bytes) -> bytes:
        if self.family_name == "srec_14080000_full":
            return data[:DUAL_GROUP_SEGMENT_SIZE]
        if self.family_name == "srec_800000_full":
            first_window = data[:SREC_800000_MIRROR_OFFSET]
            second_window = data[SREC_800000_MIRROR_OFFSET : SREC_800000_TOTAL_IMAGE_SIZE]
            first_non_ff = [index for index, value in enumerate(first_window) if value != 0xFF]
            second_non_ff = [index for index, value in enumerate(second_window) if value != 0xFF]
            candidates: list[int] = []
            if first_non_ff:
                candidates.append(max(first_non_ff) + 1)
            if second_non_ff:
                candidates.append(max(second_non_ff) + 1)
            bin_length = max(candidates) if candidates else SEGMENT_BIN_SIZE
            bin_length = max(4, min(bin_length, len(second_window)))
            compact = bytearray([0xFF] * bin_length)
            compact[:bin_length] = first_window[:bin_length]
            for index in range(bin_length):
                if compact[index] == 0xFF and index < len(second_window):
                    compact[index] = second_window[index]
            return bytes(compact)
        if self.family_name == "srec_400000_full":
            return data[:SEGMENT_BIN_SIZE]
        if self.family_name == "intel_80000_full":
            return data[:INTEL_80000_SEGMENT_SIZE]
        if self.family_name == "srec_200000_full":
            first_window = data[:SREC_200000_MIRROR_OFFSET]
            second_window = data[SREC_200000_MIRROR_OFFSET : SREC_200000_TOTAL_IMAGE_SIZE]
            first_non_ff = [index for index, value in enumerate(first_window) if value != 0xFF]
            second_non_ff = [index for index, value in enumerate(second_window) if value != 0xFF]
            candidates: list[int] = []
            if first_non_ff:
                candidates.append(max(first_non_ff) + 1)
            if second_non_ff:
                candidates.append(max(second_non_ff) + 1)
            bin_length = max(candidates) if candidates else SEGMENT_BIN_SIZE
            bin_length = max(SEGMENT_BIN_SIZE, min(bin_length, len(second_window)))
            compact = bytearray([0xFF] * bin_length)
            compact[:bin_length] = first_window[:bin_length]
            for index in range(bin_length):
                if compact[index] == 0xFF and index < len(second_window):
                    compact[index] = second_window[index]
            return bytes(compact)
        return data

    def apply_checksum_rules(self, bin_data: bytearray) -> dict[int, bytes]:
        region = self.checksum_regions[0]
        if self.family_name in {"srec_200000", "srec_200000_full", "srec_800000", "srec_800000_full"}:
            checksum_bytes = calculate_200000_checksum(bin_data)
        elif self.family_name in {"intel_80000", "intel_80000_full"}:
            checksum_bytes = calculate_intel_80000_checksum(bin_data, seed=self.checksum_seed)
        elif self.family_name in {"srec_400000", "srec_400000_full"}:
            checksum_bytes = calculate_200000_checksum(bin_data)
        elif self.family_name in {"srec_14080000", "srec_14080000_full"}:
            checksum_bytes = self._calculate_dual_group_checksum(bin_data)
        elif region.checksum_size == 4:
            checksum_bytes = ParsedHexFile._calculate_segment_checksum(bin_data)
        else:
            checksum_bytes = self._calculate_dual_group_checksum(bin_data)
        for index, value in enumerate(checksum_bytes):
            bin_data[region.checksum_offset + index] = value
        return {1: checksum_bytes}

    def get_checksum_values(self, bin_data: bytes | bytearray) -> dict[int, bytes]:
        region = self.checksum_regions[0]
        return {1: bytes(bin_data[region.checksum_offset : region.checksum_offset + region.checksum_size])}

    def _calculate_dual_group_checksum(self, bin_data: bytes | bytearray) -> bytes:
        checksum_value = 0
        for index in range(0, DUAL_GROUP_SEGMENT_SIZE - 2, 2):
            checksum_value += (bin_data[index] << 8) | bin_data[index + 1]
        checksum_value = (-checksum_value) & 0xFFFF
        return bytes(((checksum_value >> 8) & 0xFF, checksum_value & 0xFF))

    def mirror_first_segment_to_second(self, bin_data: bytearray) -> bool:
        return False

    def build_output_lines(self, bin_data: bytes | bytearray) -> list[str]:
        if self.family_name in {"srec_200000", "srec_200000_full"}:
            image = bytearray([0xFF] * SREC_200000_TOTAL_IMAGE_SIZE)
            image[: self.full_size] = bin_data[: self.full_size]
            second_start = SREC_200000_MIRROR_OFFSET
            image[second_start : second_start + self.full_size] = bin_data[: self.full_size]
            lines: list[str] = []
            for offset in range(0, len(image), SREC_200000_RECORD_DATA_SIZE):
                chunk = bytes(image[offset : offset + SREC_200000_RECORD_DATA_SIZE])
                if not chunk or all(value == 0xFF for value in chunk):
                    continue
                lines.append(
                    encode_srecord(
                        SRecord(
                            record_type="3",
                            count=0,
                            address=SREC_200000_BASE + offset,
                            data=chunk,
                            checksum=0,
                            line_number=0,
                        )
                    )
                )
            lines.append(encode_srecord(SRecord(record_type="7", count=0, address=0, data=b"", checksum=0, line_number=0)))
            return lines
        if self.family_name in {"srec_800000", "srec_800000_full"}:
            return build_800000_family_lines(bin_data)
        if self.family_name in {"intel_80000", "intel_80000_full"}:
            return build_intel_80000_hex_lines(bin_data)
        if self.family_name in {"srec_400000", "srec_400000_full"}:
            return build_400000_family_lines(
                bin_data,
                record_data_size=SREC_400000_SOURCE_RECORD_DATA_SIZE,
                checksum_mode="400000_s3fd",
            )
        if self.family_name in {"srec_14080000", "srec_14080000_full"}:
            return build_shifted_mirrored_s3_lines(
                bin_data,
                start_address=SREC_14080000_START,
                prefix_pad=SREC_14080000_PREFIX_PAD,
                record_data_size=SREC_14080000_RECORD_DATA_SIZE,
            )
        if self.family_name == "intel_60000000":
            return build_fixed_60000000_hex_lines(bytes(bin_data))
        return build_a020_dual_group_hex_lines(bin_data)


class HexBinToolApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("HEX BIN 编辑工具")
        self.root.geometry("1360x860")

        self.hex_file: ParsedHexFile | ParsedIntel80000File | ParsedSrec200000File | ParsedSrec800000File | ParsedSrec400000File | ParsedSrec14080000File | ParsedSrecFile | ParsedBinFile | None = None
        self.current_path: Path | None = None
        self.status_text = tk.StringVar(value="请选择一个 HEX 或 BIN 文件。")
        self.jump_address_text = tk.StringVar()
        self._suppress_editor_events = False
        self._auto_calc_after_id: str | None = None

        self._build_ui()

    def _build_ui(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=tk.X)

        ttk.Button(top, text="打开HEX/BIN", command=self.open_file).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(top, text="显示数据", command=self.display_bin).pack(side=tk.LEFT, padx=8)
        ttk.Button(top, text="保存HEX", command=self.save_hex).pack(side=tk.LEFT, padx=8)
        ttk.Button(top, text="保存BIN", command=self.save_bin).pack(side=tk.LEFT, padx=8)

        ttk.Label(top, textvariable=self.status_text).pack(side=tk.LEFT, padx=16)

        content = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        left = ttk.Frame(content, padding=8)
        right = ttk.Frame(content, padding=8)
        content.add(left, weight=1)
        content.add(right, weight=4)

        ttk.Label(left, text="分段信息").pack(anchor=tk.W)
        self.segment_text = ScrolledText(left, height=18, width=46, font=(MONOSPACE_FONT, 10), state=tk.DISABLED)
        self.segment_text.pack(fill=tk.BOTH, expand=True, pady=(6, 10))

        ttk.Label(left, text="总校验结果").pack(anchor=tk.W)
        self.checksum_text = ScrolledText(left, height=18, width=46, font=(MONOSPACE_FONT, 10), state=tk.DISABLED)
        self.checksum_text.pack(fill=tk.BOTH, expand=True, pady=(6, 0))

        ttk.Label(right, text="HEX + ASCII 联动编辑区").pack(anchor=tk.W)
        search_bar = ttk.Frame(right)
        search_bar.pack(fill=tk.X, pady=(6, 4))
        ttk.Label(search_bar, text="跳转地址").pack(side=tk.LEFT)
        self.jump_entry = ttk.Entry(search_bar, textvariable=self.jump_address_text, width=18)
        self.jump_entry.pack(side=tk.LEFT, padx=(6, 6))
        self.jump_entry.bind("<Return>", self.jump_to_address)
        ttk.Button(search_bar, text="跳转", command=self.jump_to_address).pack(side=tk.LEFT)
        ttk.Label(search_bar, text="支持 0x2047F0 或 47F0", foreground="#666666").pack(side=tk.LEFT, padx=(10, 0))

        self.editor_header = tk.Text(
            right,
            height=1,
            wrap=tk.NONE,
            font=(MONOSPACE_FONT, EDITOR_FONT_SIZE),
            relief=tk.FLAT,
            borderwidth=0,
            highlightthickness=0,
            takefocus=0,
        )
        self.editor_header.pack(fill=tk.X, pady=(6, 0))
        self.editor_header.insert("1.0", format_editor_header_line())
        self.editor_header.config(state=tk.DISABLED)

        self.editor = ScrolledText(right, wrap=tk.NONE, font=(MONOSPACE_FONT, EDITOR_FONT_SIZE))
        self.editor.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
        self.editor.bind("<KeyPress>", self.on_editor_keypress)
        self.editor.bind("<ButtonRelease-1>", self.on_editor_click)
        self.editor.bind("<FocusIn>", self.on_editor_focus)
        self.editor.bind("<<Paste>>", lambda _event: "break")
        self.editor.bind("<<Cut>>", lambda _event: "break")

    def set_text(self, widget: ScrolledText, value: str) -> None:
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", value)
        widget.config(state=tk.DISABLED)

    def open_file(self) -> None:
        if self._auto_calc_after_id:
            self.root.after_cancel(self._auto_calc_after_id)
            self._auto_calc_after_id = None
        file_path = filedialog.askopenfilename(
            title="打开 HEX 或 BIN 文件",
            filetypes=[
                ("HEX/BIN Files", "*.hex *.HEX *.hex_tmp *.s19 *.S19 *.s28 *.S28 *.s37 *.S37 *.mot *.MOT *.srec *.SREC *.bin *.BIN"),
                ("HEX Files", "*.hex *.HEX *.hex_tmp *.s19 *.S19 *.s28 *.S28 *.s37 *.S37 *.mot *.MOT *.srec *.SREC"),
                ("BIN Files", "*.bin *.BIN"),
                ("All Files", "*.*"),
            ],
        )
        if not file_path:
            return

        path = Path(file_path)
        suffix = path.suffix.lower()
        try:
            if suffix == ".bin":
                parsed = ParsedBinFile.from_path(path)
            else:
                file_format = detect_text_file_format(path)
                if file_format == "intel":
                    intel_records = parse_intel_hex(path)
                    if detect_intel_80000_family(intel_records):
                        parsed = ParsedIntel80000File(path=path, records=intel_records)
                    else:
                        parsed = ParsedHexFile(path=path, records=intel_records)
                else:
                    raw_srec_lines = [line for _line_number, line in read_srecord_lines(path)]
                    try:
                        srec_records = parse_srecord(path)
                        srec_checksum_mode = "standard"
                    except ValueError as standard_exc:
                        srec_records = parse_srecord(path, checksum_mode="400000_s3fd")
                        if not detect_srec_400000_family(srec_records):
                            raise standard_exc
                        srec_checksum_mode = "400000_s3fd"

                    first_data_line = next((line for line in raw_srec_lines if line.startswith("S3")), "")
                    if detect_srec_14080000_family(srec_records):
                        parsed = ParsedSrec14080000File(path=path, records=srec_records)
                    elif detect_srec_800000_family(srec_records):
                        parsed = ParsedSrec800000File(path=path, records=srec_records)
                    elif detect_srec_200000_family(srec_records):
                        parsed = ParsedSrec200000File(path=path, records=srec_records)
                    elif detect_srec_400000_family(srec_records):
                        record_data_size = (
                            SREC_400000_SOURCE_RECORD_DATA_SIZE
                            if first_data_line.startswith("S3FD")
                            else SREC_400000_BIN_RECORD_DATA_SIZE
                        )
                        parsed = ParsedSrec400000File(
                            path=path,
                            records=srec_records,
                            original_lines=raw_srec_lines,
                            output_record_data_size=record_data_size,
                            output_checksum_mode=srec_checksum_mode,
                        )
                    else:
                        parsed = ParsedSrecFile(path=path, records=srec_records)
        except Exception as exc:
            self.status_text.set(f"打开失败: {exc}")
            messagebox.showerror("打开失败", str(exc))
            return

        self.hex_file = parsed
        self.current_path = path
        self.display_bin()
        self.refresh_side_panels()
        self.status_text.set(f"已打开: {self.current_path}，可直接修改 HEX 区或 ASCII 区，系统会自动重算校验。")

    def display_bin(self) -> None:
        if not self.hex_file:
            messagebox.showinfo("提示", "请先打开 HEX 或 BIN 文件。")
            return
        self._replace_editor_content(format_editor_text(self._display_bin_data(), self._display_base_address()))

    def jump_to_address(self, _event: tk.Event | None = None) -> None:
        if not self.hex_file:
            messagebox.showinfo("提示", "请先打开 HEX 或 BIN 文件。")
            return

        raw = self.jump_address_text.get().strip().replace(" ", "").replace("_", "")
        if not raw:
            messagebox.showinfo("提示", "请输入地址，例如 2047F0 或 47F0。")
            return

        if raw.lower().startswith("0x"):
            raw = raw[2:]

        try:
            value = int(raw, 16)
        except ValueError:
            messagebox.showerror("跳转失败", f"不是有效的十六进制地址: {self.jump_address_text.get()}")
            return

        base_address = self._display_base_address()
        display_size = self._display_size()
        display_end = base_address + display_size - 1

        if base_address <= value <= display_end:
            absolute_address = value
        elif 0 <= value < display_size:
            absolute_address = base_address + value
        elif 0 <= value < self.hex_file.full_size:
            absolute_address = base_address + value
        else:
            messagebox.showerror(
                "跳转失败",
                f"地址 0x{value:X} 不在当前显示范围内。\n"
                f"显示范围: 0x{base_address:X} - 0x{display_end:X}",
            )
            return

        offset = absolute_address - base_address
        if offset < 0:
            messagebox.showerror("跳转失败", f"地址 0x{absolute_address:X} 无法定位。")
            return

        line_no = offset // BYTES_PER_LINE + 1
        if offset >= self.hex_file.full_size:
            self.editor.see(f"{line_no}.0")
            self.editor.focus_set()
            self.status_text.set(f"已跳转到 0x{absolute_address:X}，但该位置是显示补位，不可编辑。")
            return

        self._set_insert_target(EditTarget(offset=offset, region="hex", nibble=0))
        self.editor.focus_set()
        self.status_text.set(f"已跳转到 0x{absolute_address:X}")

    def on_editor_keypress(self, event: tk.Event) -> str | None:
        if not self.hex_file:
            return None

        ctrl_pressed = bool(event.state & 0x4)
        if ctrl_pressed:
            return None

        if event.keysym in {"Left", "Right", "Up", "Down", "Home", "End", "Prior", "Next"}:
            return None

        current_target = self._target_from_index(self.editor.index(tk.INSERT), snap=True)
        if current_target is None:
            return "break"

        if event.keysym == "Tab":
            self._set_insert_target(self._advance_target(current_target, 1))
            return "break"

        if event.keysym == "BackSpace":
            self._set_insert_target(self._advance_target(current_target, -1))
            return "break"

        if event.keysym == "Delete":
            self._set_insert_target(self._advance_target(current_target, 1))
            return "break"

        if current_target.region == "hex" and len(event.char) == 1 and event.char.upper() in "0123456789ABCDEF":
            self._apply_hex_edit(current_target, event.char.upper())
            return "break"

        if current_target.region == "ascii" and len(event.char) == 1 and event.char.isprintable():
            self._apply_ascii_edit(current_target, event.char)
            return "break"

        if len(event.char) == 1 and event.char.isprintable():
            return "break"

        return None

    def on_editor_click(self, _event: tk.Event | None = None) -> None:
        self.root.after_idle(self._snap_cursor_to_editable)

    def on_editor_focus(self, _event: tk.Event | None = None) -> None:
        self.root.after_idle(self._snap_cursor_to_editable)

    def _apply_hex_edit(self, target: EditTarget, hex_char: str) -> None:
        assert self.hex_file is not None
        old_value = self.hex_file.current_full_bin[target.offset]
        nibble_value = int(hex_char, 16)
        if target.nibble == 0:
            new_value = (nibble_value << 4) | (old_value & 0x0F)
            next_target = EditTarget(offset=target.offset, region="hex", nibble=1)
        else:
            new_value = (old_value & 0xF0) | nibble_value
            next_target = EditTarget(
                offset=min(self.hex_file.full_size - 1, target.offset + 1),
                region="hex",
                nibble=0,
            )
        self.hex_file.current_full_bin[target.offset] = new_value
        self._refresh_offsets({target.offset})
        self._set_insert_target(next_target)
        self._schedule_auto_recalculate()

    def _apply_ascii_edit(self, target: EditTarget, char: str) -> None:
        assert self.hex_file is not None
        self.hex_file.current_full_bin[target.offset] = ord(char)
        self._refresh_offsets({target.offset})
        self._set_insert_target(self._advance_target(target, 1))
        self._schedule_auto_recalculate()

    def _schedule_auto_recalculate(self) -> None:
        if self._auto_calc_after_id:
            self.root.after_cancel(self._auto_calc_after_id)
        self._auto_calc_after_id = self.root.after(250, self.auto_recalculate_from_editor)

    def _refresh_offsets(self, offsets: set[int]) -> None:
        for line_no in sorted({offset // BYTES_PER_LINE + 1 for offset in offsets}):
            self._replace_editor_line(line_no + EDITOR_HEADER_LINES)

    def _replace_editor_line(self, line_no: int) -> None:
        assert self.hex_file is not None
        line_text = format_editor_line(
            self._display_bin_data(),
            self._display_base_address(),
            line_no - EDITOR_HEADER_LINES - 1,
        )
        self._suppress_editor_events = True
        self.editor.delete(f"{line_no}.0", f"{line_no}.end")
        self.editor.insert(f"{line_no}.0", line_text)
        self._suppress_editor_events = False

    def _replace_editor_content(self, text: str, preserve_view: bool = False) -> None:
        insert_index = self.editor.index(tk.INSERT) if preserve_view else None
        yview = self.editor.yview() if preserve_view else None
        xview = self.editor.xview() if preserve_view else None
        self._suppress_editor_events = True
        self.editor.delete("1.0", tk.END)
        self.editor.insert("1.0", text)
        self._suppress_editor_events = False
        if preserve_view and insert_index is not None:
            try:
                self.editor.mark_set(tk.INSERT, insert_index)
            except tk.TclError:
                pass
            if yview is not None:
                self.editor.yview_moveto(yview[0])
            if xview is not None:
                self.editor.xview_moveto(xview[0])

    def _snap_cursor_to_editable(self) -> None:
        target = self._target_from_index(self.editor.index(tk.INSERT), snap=True)
        if target is not None:
            self._set_insert_target(target)

    def _target_from_index(self, index: str, snap: bool = False) -> EditTarget | None:
        if not self.hex_file:
            return None
        line_no, column = self._parse_index(index)
        if line_no <= EDITOR_HEADER_LINES:
            return None
        line_index = line_no - EDITOR_HEADER_LINES - 1
        line_start_offset = line_index * BYTES_PER_LINE
        if line_start_offset >= self.hex_file.full_size:
            return None
        bytes_in_line = min(BYTES_PER_LINE, self.hex_file.full_size - line_start_offset)

        for byte_in_line in range(bytes_in_line):
            start_col = hex_cell_start_column(byte_in_line)
            if start_col <= column < start_col + 2:
                return EditTarget(offset=line_start_offset + byte_in_line, region="hex", nibble=column - start_col)
            next_start = hex_cell_start_column(byte_in_line + 1) if byte_in_line + 1 < bytes_in_line else EDITOR_ASCII_START
            if start_col + 2 <= column < next_start:
                if snap and byte_in_line + 1 < bytes_in_line:
                    return EditTarget(offset=line_start_offset + byte_in_line + 1, region="hex", nibble=0)
                if snap:
                    return EditTarget(offset=line_start_offset + byte_in_line, region="hex", nibble=1)
                return None

        ascii_end = EDITOR_ASCII_START + bytes_in_line
        if EDITOR_ASCII_START <= column < ascii_end:
            return EditTarget(offset=line_start_offset + (column - EDITOR_ASCII_START), region="ascii")

        if not snap:
            return None
        if column < EDITOR_ASCII_START:
            if column < EDITOR_HEX_START:
                return EditTarget(offset=line_start_offset, region="hex", nibble=0)
            return EditTarget(offset=line_start_offset + bytes_in_line - 1, region="hex", nibble=1)
        return EditTarget(offset=line_start_offset + bytes_in_line - 1, region="ascii")

    def _advance_target(self, target: EditTarget, step: int) -> EditTarget:
        assert self.hex_file is not None
        if target.region == "hex":
            if step == 0:
                return target
            if step > 0:
                if target.nibble == 0:
                    return EditTarget(offset=target.offset, region="hex", nibble=1)
                new_offset = min(self.hex_file.full_size - 1, target.offset + 1)
                return EditTarget(offset=new_offset, region="hex", nibble=0)
            if target.nibble == 1:
                return EditTarget(offset=target.offset, region="hex", nibble=0)
            new_offset = max(0, target.offset - 1)
            return EditTarget(offset=new_offset, region="hex", nibble=1)

        new_offset = min(max(target.offset + step, 0), self.hex_file.full_size - 1)
        return EditTarget(offset=new_offset, region="ascii")

    def _set_insert_target(self, target: EditTarget) -> None:
        index = self._index_from_target(target)
        self.editor.mark_set(tk.INSERT, index)
        self.editor.see(index)

    @staticmethod
    def _index_from_target(target: EditTarget) -> str:
        line_no = target.offset // BYTES_PER_LINE + 1 + EDITOR_HEADER_LINES
        byte_in_line = target.offset % BYTES_PER_LINE
        if target.region == "hex":
            column = hex_cell_start_column(byte_in_line) + target.nibble
        else:
            column = EDITOR_ASCII_START + byte_in_line
        return f"{line_no}.{column}"

    @staticmethod
    def _parse_index(index: str) -> tuple[int, int]:
        line_text, column_text = index.split(".")
        return int(line_text), int(column_text)

    def auto_recalculate_from_editor(self) -> None:
        self._auto_calc_after_id = None
        if not self.hex_file:
            return
        try:
            before = self.hex_file.get_checksum_values(self.hex_file.current_full_bin)
            after = self.hex_file.apply_checksum_rules(self.hex_file.current_full_bin)
            changed_offsets: set[int] = set()
            for segment_index, new_value in after.items():
                old_value = before.get(segment_index, b"")
                if old_value != new_value:
                    region = self.hex_file.checksum_regions[segment_index - 1]
                    for index in range(region.checksum_size):
                        changed_offsets.add(region.checksum_offset + index)
            if changed_offsets:
                self._refresh_offsets(changed_offsets)
            self.refresh_side_panels()
            self.status_text.set("内容已更新，HEX 与 ASCII 已同步，校验已自动重算。")
        except Exception as exc:
            self.status_text.set(f"自动计算失败: {exc}")

    def save_hex(self) -> None:
        if not self.hex_file:
            messagebox.showinfo("提示", "请先打开 HEX 或 BIN 文件。")
            return
        try:
            self.hex_file.mirror_first_segment_to_second(self.hex_file.current_full_bin)
            self.hex_file.apply_checksum_rules(self.hex_file.current_full_bin)
            lines = self.hex_file.build_output_lines(self.hex_file.current_full_bin)
        except Exception as exc:
            messagebox.showerror("保存失败", str(exc))
            return

        default_name = self.current_path.stem + "_edited.hex" if self.current_path else "output.hex"
        file_path = filedialog.asksaveasfilename(
            title="保存 HEX 文件",
            defaultextension=".hex",
            initialfile=default_name,
            filetypes=[("HEX Files", "*.hex"), ("All Files", "*.*")],
        )
        if not file_path:
            return

        try:
            if hasattr(self.hex_file, "build_output_bytes"):
                output_bytes = self.hex_file.build_output_bytes(self.hex_file.current_full_bin)
                Path(file_path).write_bytes(output_bytes)
            else:
                Path(file_path).write_text("\n".join(lines) + "\n", encoding="ascii")
        except Exception as exc:
            messagebox.showerror("保存失败", str(exc))
            return

        self.display_bin()
        self.refresh_side_panels()
        self.status_text.set(f"已保存: {file_path}")

    def save_bin(self) -> None:
        if not self.hex_file:
            messagebox.showinfo("提示", "请先打开 HEX 或 BIN 文件。")
            return
        try:
            self.hex_file.mirror_first_segment_to_second(self.hex_file.current_full_bin)
            self.hex_file.apply_checksum_rules(self.hex_file.current_full_bin)
        except Exception as exc:
            messagebox.showerror("保存失败", str(exc))
            return

        default_name = self.current_path.stem + "_edited.bin" if self.current_path else "output.bin"
        file_path = filedialog.asksaveasfilename(
            title="保存 BIN 文件",
            defaultextension=".bin",
            initialfile=default_name,
            filetypes=[("BIN Files", "*.bin"), ("All Files", "*.*")],
        )
        if not file_path:
            return

        try:
            Path(file_path).write_bytes(bytes(self.hex_file.current_full_bin))
        except Exception as exc:
            messagebox.showerror("保存失败", str(exc))
            return

        self.display_bin()
        self.refresh_side_panels()
        self.status_text.set(f"已保存BIN: {file_path}")

    def refresh_side_panels(self) -> None:
        if not self.hex_file:
            return
        self.set_text(self.segment_text, self._build_segment_text_display_v2())
        self.set_text(self.checksum_text, self._build_checksum_text_display_v2())

    def _display_base_address(self) -> int:
        assert self.hex_file is not None
        return getattr(self.hex_file, "display_base_address", self.hex_file.min_address)

    def _display_delta(self) -> int:
        assert self.hex_file is not None
        return self._display_base_address() - self.hex_file.min_address

    def _display_size(self) -> int:
        assert self.hex_file is not None
        return max(getattr(self.hex_file, "display_size", self.hex_file.full_size), self.hex_file.full_size)

    def _display_bin_data(self) -> bytes | bytearray:
        assert self.hex_file is not None
        display_size = self._display_size()
        if display_size <= self.hex_file.full_size:
            return self.hex_file.current_full_bin
        padded = bytearray([0xFF] * display_size)
        padded[: self.hex_file.full_size] = self.hex_file.current_full_bin
        return padded

    def _build_segment_text_display(self) -> str:
        assert self.hex_file is not None
        lines = [
            f"文件: {self.hex_file.path}",
            f"类型: {self.hex_file.mode_name}",
            f"识别家族: {getattr(self.hex_file, 'family_label', '未标记')}",
            f"校验类型: {self.hex_file.checksum_scheme_name}",
            "",
            f"最小地址/偏移: {format_address_text(self.hex_file.min_address)}",
            f"最大地址/偏移: {format_address_text(self.hex_file.max_address)}",
            f"完整数据长度: {self.hex_file.full_size} 字节 (0x{self.hex_file.full_size:X})",
            f"实际数据字节: {len(self.hex_file.data_addresses)} 字节",
            f"数据记录数: {self.hex_file.data_record_count}",
            f"扩展地址记录数: {self.hex_file.ext_record_count}",
            f"连续段数: {len(self.hex_file.segments)}",
            "",
            "说明:",
            "右侧左半部分是十六进制，右半部分是 ASCII，对应同一批字节。",
            "修改任意一边，另一边会自动同步；保存 HEX 时会自动重算校验。",
            "",
            "连续段列表:",
        ]
        for index, (start, end) in enumerate(self.hex_file.segments, start=1):
            length = end - start + 1
            lines.append(
                f"{index:02d}. 起始 {format_address_text(start)}  结束 {format_address_text(end)}  长度 {length} (0x{length:X})"
            )
        return "\n".join(lines)

    def _build_checksum_text_display(self) -> str:
        assert self.hex_file is not None
        current_values = self.hex_file.get_checksum_values(self.hex_file.current_full_bin)
        if not self.hex_file.checksum_regions:
            return "未发现可自动回写的总校验区。当前文件仍可正常编辑和保存，行校验会自动更新。"

        lines = ["原始校验 / 当前校验", ""]
        for region in self.hex_file.checksum_regions:
            original_value = self.hex_file.original_checksum_values[region.segment_index].hex(" ").upper()
            current_value = current_values[region.segment_index].hex(" ").upper()
            checksum_start = region.start_address + (region.checksum_offset - region.start_offset)
            lines.append(
                f"段{region.segment_index}  末尾地址 {format_address_text(checksum_start)}"
                f"-{format_address_text(region.end_address)}  原始 {original_value}  当前 {current_value}"
            )
        return "\n".join(lines)

    def _build_segment_text_display_v2(self) -> str:
        assert self.hex_file is not None
        display_delta = self._display_delta()
        display_size = self._display_size()
        display_max = self.hex_file.min_address + display_delta + display_size - 1
        actual_max = self.hex_file.max_address + display_delta
        lines = [
            f"文件: {self.hex_file.path}",
            f"类型: {self.hex_file.mode_name}",
            f"识别家族: {getattr(self.hex_file, 'family_label', '未标记')}",
            f"校验类型: {self.hex_file.checksum_scheme_name}",
            "",
            f"最小地址/偏移: {format_address_text(self.hex_file.min_address + display_delta)}",
            f"实际结束: {format_address_text(actual_max)}",
            f"显示结束: {format_address_text(display_max)}",
            f"完整数据长度: {self.hex_file.full_size} 字节 (0x{self.hex_file.full_size:X})",
            f"实际数据字节: {len(self.hex_file.data_addresses)} 字节",
            f"数据记录数: {self.hex_file.data_record_count}",
            f"扩展地址记录数: {self.hex_file.ext_record_count}",
            f"连续段数: {len(self.hex_file.segments)}",
            "",
            "说明:",
            "右侧左半部分是十六进制，右半部分是 ASCII，对应同一批字节。",
            "修改任意一边，另一边会自动同步；保存 HEX 时会自动重算校验。",
            "",
            "连续段列表:",
        ]
        for index, (start, end) in enumerate(self.hex_file.segments, start=1):
            length = end - start + 1
            display_end = end + display_delta
            if index == 1 and display_size > self.hex_file.full_size:
                display_end = start + display_delta + display_size - 1
            lines.append(
                f"{index:02d}. 起始 {format_address_text(start + display_delta)}  结束 {format_address_text(display_end)}  长度 {length} (0x{length:X})"
            )
        return "\n".join(lines)

    def _build_checksum_text_display_v2(self) -> str:
        assert self.hex_file is not None
        display_delta = self._display_delta()
        current_values = self.hex_file.get_checksum_values(self.hex_file.current_full_bin)
        if not self.hex_file.checksum_regions:
            return "未发现可自动回写的总校验区。当前文件仍可正常编辑和保存，行校验会自动更新。"

        lines = ["原始校验 / 当前校验", ""]
        for region in self.hex_file.checksum_regions:
            original_value = self.hex_file.original_checksum_values[region.segment_index].hex(" ").upper()
            current_value = current_values[region.segment_index].hex(" ").upper()
            checksum_start = region.start_address + (region.checksum_offset - region.start_offset) + display_delta
            checksum_end = region.end_address + display_delta
            checksum_line_start = checksum_start & ~0xF
            lines.append(
                f"段{region.segment_index}  校验行 {format_address_text(checksum_line_start)}"
                f"  末字节地址 {format_address_text(checksum_end)}"
                f"  校验范围 {format_address_text(checksum_start)}-{format_address_text(checksum_end)}"
                f"  原始 {original_value}  当前 {current_value}"
            )
            if isinstance(self.hex_file, ParsedSrec200000File):
                mirror_start = SREC_200000_SECOND_BASE + (region.checksum_offset - region.start_offset)
                mirror_end = SREC_200000_SECOND_BASE + (region.end_address - region.start_address)
                mirror_line_start = mirror_start & ~0xF
                lines.append(
                    f"镜像段  校验行 {format_address_text(mirror_line_start)}"
                    f"  末字节地址 {format_address_text(mirror_end)}"
                    f"  校验范围 {format_address_text(mirror_start)}-{format_address_text(mirror_end)}"
                    f"  原始 {original_value}  当前 {current_value}"
                )
        return "\n".join(lines)

    def build_segment_text(self) -> str:
        assert self.hex_file is not None
        lines = [
            f"文件: {self.hex_file.path}",
            f"类型: {self.hex_file.mode_name}",
            f"识别家族: {getattr(self.hex_file, 'family_label', '未标记')}",
            f"校验类型: {self.hex_file.checksum_scheme_name}",
            "",
            f"最小地址/偏移: 0x{self.hex_file.min_address:08X}",
            f"最大地址/偏移: 0x{self.hex_file.max_address:08X}",
            f"完整数据长度: {self.hex_file.full_size} 字节 (0x{self.hex_file.full_size:X})",
            f"实际数据字节: {len(self.hex_file.data_addresses)} 字节",
            f"数据记录数: {self.hex_file.data_record_count}",
            f"扩展地址记录数: {self.hex_file.ext_record_count}",
            f"连续段数: {len(self.hex_file.segments)}",
            "",
            "说明:",
            "右侧左半部分是十六进制，右半部分是 ASCII，对应同一批字节。",
            "修改任意一边，另一边会自动同步；保存 HEX 时会自动重算校验。",
            "",
            "连续段列表:",
        ]
        for index, (start, end) in enumerate(self.hex_file.segments, start=1):
            length = end - start + 1
            lines.append(f"{index:02d}. 起始 0x{start:08X}  结束 0x{end:08X}  长度 {length} (0x{length:X})")
        return "\n".join(lines)

    def build_checksum_text(self) -> str:
        assert self.hex_file is not None
        current_values = self.hex_file.get_checksum_values(self.hex_file.current_full_bin)
        if not self.hex_file.checksum_regions:
            return "未发现可自动回写的总校验区。当前文件仍可正常编辑和保存，行校验会自动更新。"

        lines = ["原始校验 / 当前校验", ""]
        for region in self.hex_file.checksum_regions:
            original_value = self.hex_file.original_checksum_values[region.segment_index].hex(" ").upper()
            current_value = current_values[region.segment_index].hex(" ").upper()
            checksum_start = region.start_address + (region.checksum_offset - region.start_offset)
            lines.append(
                f"段 {region.segment_index}  末尾地址 0x{checksum_start:08X}"
                f"-0x{region.end_address:08X}  原始 {original_value}  当前 {current_value}"
            )
        return "\n".join(lines)


def main() -> None:
    root = tk.Tk()
    HexBinToolApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
