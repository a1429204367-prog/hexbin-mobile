from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
tk = None
filedialog = messagebox = ttk = ScrolledText = None


BYTES_PER_LINE = 16
MONOSPACE_FONT = "Courier New"
EDITOR_FONT_SIZE = 12
HEX_GROUP_BREAK_INDEX = 8
HEX_GROUP_EXTRA_SPACES = 1
EDITOR_HEX_START = 10
EDITOR_HEX_WIDTH = BYTES_PER_LINE * 3 - 1 + HEX_GROUP_EXTRA_SPACES
EDITOR_ASCII_START = EDITOR_HEX_START + EDITOR_HEX_WIDTH + 2
DUPLICATED_PARAMETER_SEGMENT_SIZE = 0x2000
DUPLICATED_PARAMETER_BASE_ADDRESSES = frozenset({0x4000, 0x84000})


@dataclass
class EditTarget:
    offset: int
    region: str
    nibble: int = 0


@dataclass
class IntelRecord:
    raw_line: str
    byte_count: int
    address: int
    record_type: int
    data: bytes
    checksum: int
    absolute_address: int | None = None


@dataclass
class SrecRecord:
    raw_line: str
    record_type: str
    count: int
    address: int
    data: bytes
    checksum: int


@dataclass
class LoadedImage:
    path: Path
    source_format: str
    base_address: int
    data: bytearray
    source_suffix: str = ""
    line_ending: str = "\n"
    has_trailing_newline: bool = True
    intel_records: list[IntelRecord] | None = None
    srec_records: list[SrecRecord] | None = None
    display_base_address: int | None = None
    display_end_address: int | None = None
    srec_first_data_address: int | None = None
    srec_last_data_end_address: int | None = None
    srec_execution_record_type: str | None = None
    srec_execution_address: int | None = None
    layout_label: str = "单段式"
    logical_segment_size: int | None = None
    save_duplicate_span: int | None = None
    save_duplicate_count: int = 1
    mirror_span: int | None = None
    mirror_base_offset: int = 0

    @property
    def end_address(self) -> int:
        return self.base_address + len(self.data) - 1 if self.data else self.base_address


def safe_ascii(value: int) -> str:
    return chr(value) if 32 <= value <= 126 else "."


def format_address(address: int) -> str:
    return f"{address:X}".rjust(8)


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


def format_editor_header_line() -> str:
    hex_labels = format_hex_columns([f"{index:X}".rjust(2) for index in range(BYTES_PER_LINE)]).ljust(EDITOR_HEX_WIDTH)
    return f"{'Offset'.ljust(8)}: {hex_labels} |{' ' * BYTES_PER_LINE}|"


def format_editor_line(data: bytes | bytearray, base_address: int, line_index: int) -> str:
    offset = line_index * BYTES_PER_LINE
    chunk = data[offset : offset + BYTES_PER_LINE]
    hex_part = format_hex_columns([f"{value:02X}" for value in chunk]).ljust(EDITOR_HEX_WIDTH)
    ascii_part = "".join(safe_ascii(value) for value in chunk).ljust(BYTES_PER_LINE)
    return f"{format_address(base_address + offset)}: {hex_part} |{ascii_part}|"


def format_editor_text(data: bytes | bytearray, base_address: int) -> str:
    line_count = (len(data) + BYTES_PER_LINE - 1) // BYTES_PER_LINE
    return "\n".join(format_editor_line(data, base_address, line) for line in range(line_count))


def intel_checksum(byte_count: int, address: int, record_type: int, data: bytes) -> int:
    total = byte_count + ((address >> 8) & 0xFF) + (address & 0xFF) + record_type + sum(data)
    return (-total) & 0xFF


def encode_intel_record(address: int, record_type: int, data: bytes) -> str:
    checksum = intel_checksum(len(data), address, record_type, data)
    return f":{len(data):02X}{address:04X}{record_type:02X}{data.hex().upper()}{checksum:02X}"


def detect_line_ending(raw_bytes: bytes) -> str:
    return "\r\n" if b"\r\n" in raw_bytes else "\n"


def parse_intel_hex(path: Path) -> LoadedImage:
    memory: dict[int, int] = {}
    upper = 0
    records: list[IntelRecord] = []
    raw_bytes = path.read_bytes()
    line_ending = detect_line_ending(raw_bytes)
    has_trailing_newline = raw_bytes.endswith(line_ending.encode("ascii"))
    with path.open("r", encoding="ascii", errors="strict", newline="") as fp:
        for line_number, raw in enumerate(fp, start=1):
            line = raw.strip()
            if not line:
                continue
            if not line.startswith(":"):
                raise ValueError(f"第 {line_number} 行不是 Intel HEX 记录。")
            try:
                byte_count = int(line[1:3], 16)
                address = int(line[3:7], 16)
                record_type = int(line[7:9], 16)
                data = bytes.fromhex(line[9 : 9 + byte_count * 2])
                checksum = int(line[9 + byte_count * 2 : 11 + byte_count * 2], 16)
            except ValueError as exc:
                raise ValueError(f"第 {line_number} 行格式错误。") from exc
            if len(data) != byte_count or intel_checksum(byte_count, address, record_type, data) != checksum:
                raise ValueError(f"第 {line_number} 行 Intel HEX 单行校验错误。")

            if record_type == 0x00:
                absolute = upper + address
                for index, value in enumerate(data):
                    memory[absolute + index] = value
                absolute_address = absolute
            elif record_type == 0x01:
                absolute_address = None
                records.append(
                    IntelRecord(
                        raw_line=line,
                        byte_count=byte_count,
                        address=address,
                        record_type=record_type,
                        data=data,
                        checksum=checksum,
                        absolute_address=absolute_address,
                    )
                )
                break
            elif record_type == 0x02:
                if byte_count != 2:
                    raise ValueError(f"第 {line_number} 行扩展段地址长度错误。")
                upper = int.from_bytes(data, "big") << 4
                absolute_address = None
            elif record_type == 0x04:
                if byte_count != 2:
                    raise ValueError(f"第 {line_number} 行扩展线性地址长度错误。")
                upper = int.from_bytes(data, "big") << 16
                absolute_address = None
            else:
                absolute_address = None

            records.append(
                IntelRecord(
                    raw_line=line,
                    byte_count=byte_count,
                    address=address,
                    record_type=record_type,
                    data=data,
                    checksum=checksum,
                    absolute_address=absolute_address,
                )
            )

    if not memory:
        raise ValueError("文件里没有数据记录。")
    image = image_from_memory(path, "Intel HEX", memory)
    image.source_suffix = path.suffix.lower()
    image.line_ending = line_ending
    image.has_trailing_newline = has_trailing_newline
    image.intel_records = records
    return image


def srec_address_length(record_type: str) -> int:
    if record_type in {"0", "1", "5", "9"}:
        return 2
    if record_type in {"2", "6", "8"}:
        return 3
    if record_type in {"3", "7"}:
        return 4
    raise ValueError(f"不支持 S{record_type} 记录。")


def srec_checksum(record_type: str, address: int, data: bytes, count_override: int | None = None) -> int:
    address_length = srec_address_length(record_type)
    count = address_length + len(data) + 1 if count_override is None else count_override
    total = count
    for shift in range((address_length - 1) * 8, -1, -8):
        total += (address >> shift) & 0xFF
    total += sum(data)
    return (~total) & 0xFF


def encode_srec_record(record_type: str, address: int, data: bytes, count_override: int | None = None) -> str:
    address_length = srec_address_length(record_type)
    count = address_length + len(data) + 1 if count_override is None else count_override
    checksum = srec_checksum(record_type, address, data, count_override=count)
    return f"S{record_type}{count:02X}{address:0{address_length * 2}X}{data.hex().upper()}{checksum:02X}"


def parse_srecord(path: Path) -> LoadedImage:
    memory: dict[int, int] = {}
    records: list[SrecRecord] = []
    first_data_address: int | None = None
    last_data_end_address: int | None = None
    execution_record_type: str | None = None
    execution_address: int | None = None
    raw_bytes = path.read_bytes()
    line_ending = detect_line_ending(raw_bytes)
    has_trailing_newline = raw_bytes.endswith(line_ending.encode("ascii"))
    with path.open("r", encoding="ascii", errors="ignore", newline="") as fp:
        for line_number, raw in enumerate(fp, start=1):
            line = raw.strip().upper()
            if not line:
                continue
            marker = line.find("S")
            if marker > 0:
                line = line[marker:]
            if not line.startswith("S") or len(line) < 4:
                continue
            record_type = line[1]
            if record_type not in {"0", "1", "2", "3", "5", "6", "7", "8", "9"}:
                continue
            try:
                address_length = srec_address_length(record_type)
                count = int(line[2:4], 16)
                payload = bytes.fromhex(line[4:])
            except ValueError as exc:
                raise ValueError(f"第 {line_number} 行 S Record 格式错误。") from exc
            if len(payload) < address_length + 1 or count < address_length + 1:
                raise ValueError(f"第 {line_number} 行 S Record 长度错误。")
            address = int.from_bytes(payload[:address_length], "big")
            data = payload[address_length:-1]
            checksum = payload[-1]
            if srec_checksum(record_type, address, data, count_override=count) != checksum:
                raise ValueError(f"第 {line_number} 行 S Record 单行校验错误。")
            records.append(
                SrecRecord(
                    raw_line=line,
                    record_type=record_type,
                    count=count,
                    address=address,
                    data=data,
                    checksum=checksum,
                )
            )
            if record_type in {"1", "2", "3"}:
                if first_data_address is None:
                    first_data_address = address
                if data:
                    last_data_end_address = address + len(data) - 1
                for index, value in enumerate(data):
                    memory[address + index] = value
            elif record_type in {"7", "8", "9"}:
                execution_record_type = record_type
                execution_address = address

    if not memory:
        raise ValueError("文件里没有 S Record 数据记录。")
    image = image_from_memory(path, "S Record", memory)
    image.source_suffix = path.suffix.lower()
    image.line_ending = line_ending
    image.has_trailing_newline = has_trailing_newline
    image.srec_records = records
    image.srec_first_data_address = first_data_address
    image.srec_last_data_end_address = last_data_end_address
    image.srec_execution_record_type = execution_record_type
    image.srec_execution_address = execution_address
    return image


def image_from_memory(path: Path, source_format: str, memory: dict[int, int]) -> LoadedImage:
    base = min(memory)
    end = max(memory)
    data = bytearray([0xFF] * (end - base + 1))
    for address, value in memory.items():
        data[address - base] = value
    return LoadedImage(path=path, source_format=source_format, base_address=base, data=data)


ADDRESS_HINTS: dict[str, tuple[int, int | None]] = {
    "SHSJF1-A.s19": (0x10008000, 0x10020E00),
    "SHSJ01-B(1).hex": (0x10001000, 0x10020E00),
    "0000(1).mot": (0x00000000, 0x000007F0),
    "1200.mot": (0x00000000, 0x0000BFF0),
    "0000(2).mot": (0x00002400, None),
    "1200(2).mot": (0x00004000, 0x0000BFF0),
}

def find_address_hint(path: Path) -> tuple[int, int | None] | None:
    hint = ADDRESS_HINTS.get(path.name)
    if hint is not None:
        return hint
    lowered_name = path.name.lower()
    if lowered_name.startswith("p203728b000g05"):
        return (0x84000, 0x85FF0)
    return None


def detect_special_layout(image: LoadedImage) -> LoadedImage:
    is_duplicated_parameter_layout = (
        image.source_format == "Intel HEX"
        and image.base_address in DUPLICATED_PARAMETER_BASE_ADDRESSES
        and len(image.data) >= DUPLICATED_PARAMETER_SEGMENT_SIZE
        and len(image.data) <= DUPLICATED_PARAMETER_SEGMENT_SIZE * 2
    )
    if is_duplicated_parameter_layout:
        image.display_base_address = image.base_address
        image.display_end_address = image.base_address + DUPLICATED_PARAMETER_SEGMENT_SIZE - 0x10
        image.logical_segment_size = DUPLICATED_PARAMETER_SEGMENT_SIZE
        second_segment = image.data[DUPLICATED_PARAMETER_SEGMENT_SIZE : DUPLICATED_PARAMETER_SEGMENT_SIZE * 2]
        has_second_segment_data = any(value != 0xFF for value in second_segment)
        if len(image.data) >= DUPLICATED_PARAMETER_SEGMENT_SIZE * 2 and has_second_segment_data:
            image.layout_label = "两段式"
            image.save_duplicate_span = DUPLICATED_PARAMETER_SEGMENT_SIZE
            image.save_duplicate_count = 2
            image.data = bytearray(image.data[:DUPLICATED_PARAMETER_SEGMENT_SIZE])
            image.mirror_span = None
            image.mirror_base_offset = 0
        else:
            image.layout_label = "单段式"
            image.mirror_span = None
            image.mirror_base_offset = 0
    return image


def apply_address_hints(image: LoadedImage) -> LoadedImage:
    hint = find_address_hint(image.path)
    if hint:
        image.display_base_address = hint[0]
        image.display_end_address = hint[1]
    elif image.source_format == "S Record" and image.srec_first_data_address is not None:
        image.display_base_address = image.srec_first_data_address
        image.display_end_address = image.srec_last_data_end_address
    return detect_special_layout(image)


def load_image(path: Path) -> LoadedImage:
    suffix = path.suffix.lower()
    if suffix == ".bin":
        return apply_address_hints(
            LoadedImage(path=path, source_format="BIN", base_address=0, data=bytearray(path.read_bytes()), source_suffix=suffix)
        )
    with path.open("r", encoding="ascii", errors="ignore") as fp:
        for raw in fp:
            line = raw.strip()
            if not line:
                continue
            if line.startswith(":"):
                return apply_address_hints(parse_intel_hex(path))
            if line.upper().startswith("S") or "S" in line.upper():
                return apply_address_hints(parse_srecord(path))
            break
    raise ValueError("无法识别文件格式，只支持 HEX / BIN / S19 / MOT。")


def save_as_bin(path: Path, image: LoadedImage) -> None:
    path.write_bytes(materialize_output_data(image))


def image_slice(image: LoadedImage, absolute_address: int, size: int) -> bytes:
    output_data = materialize_output_data(image)
    start = absolute_address - image.base_address
    return bytes(output_data[start : start + size])


def materialize_output_data(image: LoadedImage) -> bytes:
    if image.save_duplicate_span is not None and image.save_duplicate_count > 1:
        first_segment = bytes(image.data[: image.save_duplicate_span])
        return first_segment * image.save_duplicate_count
    return bytes(image.data)


def save_as_intel_hex(path: Path, image: LoadedImage) -> None:
    if image.intel_records:
        lines: list[str] = []
        for record in image.intel_records:
            if record.record_type == 0x00 and record.absolute_address is not None:
                current_data = image_slice(image, record.absolute_address, record.byte_count)
                if current_data == record.data:
                    lines.append(record.raw_line)
                else:
                    lines.append(encode_intel_record(record.address, record.record_type, current_data))
            else:
                lines.append(record.raw_line)
        text = image.line_ending.join(lines)
        if image.has_trailing_newline:
            text += image.line_ending
        path.write_text(text, encoding="ascii", newline="")
        return

    lines: list[str] = []
    current_upper: int | None = None
    output_data = materialize_output_data(image)
    for offset in range(0, len(output_data), BYTES_PER_LINE):
        absolute = image.base_address + offset
        upper = absolute >> 16
        if upper != current_upper:
            lines.append(encode_intel_record(0, 0x04, upper.to_bytes(2, "big")))
            current_upper = upper
        chunk = bytes(output_data[offset : offset + BYTES_PER_LINE])
        lines.append(encode_intel_record(absolute & 0xFFFF, 0x00, chunk))
    lines.append(encode_intel_record(0, 0x01, b""))
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def srec_types_for_suffix(suffix: str, end_address: int) -> tuple[str, str]:
    if suffix == ".s19" and end_address <= 0xFFFF:
        return "1", "9"
    if suffix == ".s28" and end_address <= 0xFFFFFF:
        return "2", "8"
    return "3", "7"


def save_as_srecord(path: Path, image: LoadedImage, suffix: str) -> None:
    if image.srec_records:
        lines: list[str] = []
        for record in image.srec_records:
            if record.record_type in {"1", "2", "3"}:
                current_data = image_slice(image, record.address, len(record.data))
                if current_data == record.data:
                    lines.append(record.raw_line)
                else:
                    lines.append(encode_srec_record(record.record_type, record.address, current_data, count_override=record.count))
            else:
                lines.append(record.raw_line)
        text = image.line_ending.join(lines)
        if image.has_trailing_newline:
            text += image.line_ending
        path.write_text(text, encoding="ascii", newline="")
        return

    data_type, end_type = srec_types_for_suffix(suffix, image.end_address)
    lines: list[str] = []
    output_data = materialize_output_data(image)
    output_end_address = image.base_address + len(output_data) - 1 if output_data else image.base_address
    data_type, end_type = srec_types_for_suffix(suffix, output_end_address)
    for offset in range(0, len(output_data), BYTES_PER_LINE):
        absolute = image.base_address + offset
        chunk = bytes(output_data[offset : offset + BYTES_PER_LINE])
        lines.append(encode_srec_record(data_type, absolute, chunk))
    lines.append(encode_srec_record(end_type, 0, b""))
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def parse_hex_search(value: str) -> bytes:
    cleaned = "".join(ch for ch in value.strip() if ch not in " _-")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned:
        raise ValueError("请输入要搜索的十六进制数字。")
    if len(cleaned) % 2:
        raise ValueError("十六进制搜索内容必须是偶数位，例如 12AB 或 12 AB。")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError("搜索内容不是有效的十六进制数字。") from exc


class LineChecksumToolApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("HEX BIN S19 MOT 单行校验编辑工具")
        self.root.geometry("1360x860")

        self.image: LoadedImage | None = None
        self.status_text = tk.StringVar(value="请选择 HEX / BIN / S19 / MOT 文件。")
        self.search_text = tk.StringVar()
        self.jump_text = tk.StringVar()
        self.last_search_offset = -1

        self._build_ui()

    def _build_ui(self) -> None:
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=tk.X)
        ttk.Button(top, text="打开", command=self.open_file).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(top, text="保存为", command=self.save_file).pack(side=tk.LEFT, padx=8)
        ttk.Label(top, textvariable=self.status_text).pack(side=tk.LEFT, padx=16)

        content = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        left = ttk.Frame(content, padding=8)
        right = ttk.Frame(content, padding=8)
        content.add(left, weight=1)
        content.add(right, weight=4)

        ttk.Label(left, text="文件信息").pack(anchor=tk.W)
        self.info_text = ScrolledText(left, height=16, width=48, font=(MONOSPACE_FONT, 10), state=tk.DISABLED)
        self.info_text.pack(fill=tk.BOTH, expand=True, pady=(6, 0))

        control = ttk.Frame(right)
        control.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(control, text="跳转地址").pack(side=tk.LEFT)
        jump_entry = ttk.Entry(control, textvariable=self.jump_text, width=16)
        jump_entry.pack(side=tk.LEFT, padx=(6, 12))
        jump_entry.bind("<Return>", self.jump_to_address)
        ttk.Button(control, text="跳转", command=self.jump_to_address).pack(side=tk.LEFT, padx=(0, 16))

        ttk.Label(control, text="搜索十六进制数值").pack(side=tk.LEFT)
        search_entry = ttk.Entry(control, textvariable=self.search_text, width=24)
        search_entry.pack(side=tk.LEFT, padx=(6, 8))
        search_entry.bind("<Return>", self.search_hex)
        ttk.Button(control, text="搜索下一个", command=self.search_hex).pack(side=tk.LEFT)

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
        self.editor_header.pack(fill=tk.X)
        self.editor_header.insert("1.0", format_editor_header_line())
        self.editor_header.config(state=tk.DISABLED)

        self.editor = ScrolledText(right, wrap=tk.NONE, font=(MONOSPACE_FONT, EDITOR_FONT_SIZE))
        self.editor.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
        self.editor.bind("<KeyPress>", self.on_editor_keypress)
        self.editor.bind("<ButtonRelease-1>", self.snap_cursor)
        self.editor.bind("<FocusIn>", self.snap_cursor)
        self.editor.bind("<<Paste>>", lambda _event: "break")
        self.editor.bind("<<Cut>>", lambda _event: "break")
        self.editor.tag_configure("search_match", background="#FFE680")

    def set_text(self, widget: ScrolledText, value: str) -> None:
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", value)
        widget.config(state=tk.DISABLED)

    def open_file(self) -> None:
        file_path = filedialog.askopenfilename(
            title="打开文件",
            filetypes=[
                ("Supported Files", "*.hex *.HEX *.bin *.BIN *.s19 *.S19 *.s28 *.S28 *.s37 *.S37 *.mot *.MOT"),
                ("All Files", "*.*"),
            ],
        )
        if not file_path:
            return
        try:
            self.image = load_image(Path(file_path))
        except Exception as exc:
            messagebox.showerror("打开失败", str(exc))
            self.status_text.set(f"打开失败: {exc}")
            return
        self.last_search_offset = -1
        self.refresh_editor()
        self.refresh_info()
        self.status_text.set(f"已打开: {self.image.path}")

    def save_file(self) -> None:
        if not self.image:
            messagebox.showinfo("提示", "请先打开文件。")
            return
        file_path = filedialog.asksaveasfilename(
            title="保存为",
            defaultextension=".hex",
            filetypes=[
                ("Intel HEX", "*.hex"),
                ("BIN", "*.bin"),
                ("S19", "*.s19"),
                ("MOT", "*.mot"),
                ("S28", "*.s28"),
                ("S37", "*.s37"),
                ("All Files", "*.*"),
            ],
        )
        if not file_path:
            return
        path = Path(file_path)
        suffix = path.suffix.lower()
        try:
            if suffix == ".bin":
                save_as_bin(path, self.image)
            elif suffix == self.image.source_suffix and self.image.source_format == "S Record":
                save_as_srecord(path, self.image, suffix)
            elif suffix == self.image.source_suffix and self.image.source_format == "Intel HEX":
                save_as_intel_hex(path, self.image)
            elif suffix == ".hex":
                save_as_intel_hex(path, self.image)
            elif suffix in {".s19", ".s28", ".s37", ".mot"}:
                save_as_srecord(path, self.image, suffix)
            else:
                raise ValueError("保存扩展名必须是 .hex / .bin / .s19 / .mot / .s28 / .s37。")
        except Exception as exc:
            messagebox.showerror("保存失败", str(exc))
            return
        self.status_text.set(f"已保存: {path}")

    def refresh_editor(self) -> None:
        assert self.image is not None
        self.editor.delete("1.0", tk.END)
        self.editor.insert("1.0", format_editor_text(self.image.data, self.image.base_address))
        self.editor.tag_remove("search_match", "1.0", tk.END)

    def refresh_info(self) -> None:
        assert self.image is not None
        display_base = self.image.display_base_address if self.image.display_base_address is not None else self.image.base_address
        display_end = self.image.display_end_address if self.image.display_end_address is not None else self.image.end_address
        lines = [
            f"文件: {self.image.path}",
            f"来源格式: {self.image.source_format}",
            f"结构识别: {self.image.layout_label}",
            "校验方式: 只计算每行格式校验",
            "",
            f"起始地址: 0x{display_base:X}",
            f"结束地址: 0x{display_end:X}",
            f"数据长度: {len(self.image.data)} 字节 (0x{len(self.image.data):X})",
            *(
                [f"单段长度: 0x{self.image.logical_segment_size:X}"]
                if self.image.logical_segment_size is not None
                else []
            ),
            *(
                ["编辑视图: 仅显示第一段，保存时自动复制生成第二段"]
                if self.image.save_duplicate_span is not None and self.image.save_duplicate_count > 1
                else []
            ),
            *(
                [
                    f"S-record首条数据地址: 0x{self.image.srec_first_data_address:X}"
                    if self.image.srec_first_data_address is not None
                    else "S-record首条数据地址: 未获取",
                    f"S-record末条数据结束: 0x{self.image.srec_last_data_end_address:X}"
                    if self.image.srec_last_data_end_address is not None
                    else "S-record末条数据结束: 未获取",
                    f"执行地址记录: S{self.image.srec_execution_record_type} 0x{self.image.srec_execution_address:X}"
                    if self.image.srec_execution_record_type is not None and self.image.srec_execution_address is not None
                    else "执行地址记录: 未获取",
                ]
                if self.image.source_format == "S Record"
                else []
            ),
            *(
                [f"镜像联动: 前后两段同步保存，单段长度 0x{self.image.mirror_span:X}"]
                if self.image.mirror_span is not None
                else []
            ),
            "",
            "保存说明:",
            "保存 HEX/S19/MOT 时会重新计算每一行校验。",
            "本工具不计算、不修改任何总校验。",
        ]
        self.set_text(self.info_text, "\n".join(lines))

    def mirror_partner_offset(self, offset: int) -> int | None:
        assert self.image is not None
        if self.image.mirror_span is None:
            return None
        start = self.image.mirror_base_offset
        span = self.image.mirror_span
        first_start = start
        second_start = start + span
        if first_start <= offset < first_start + span:
            partner = second_start + (offset - first_start)
        elif second_start <= offset < second_start + span:
            partner = first_start + (offset - second_start)
        else:
            return None
        if 0 <= partner < len(self.image.data):
            return partner
        return None

    def apply_mirror_link(self, offset: int) -> set[int]:
        assert self.image is not None
        changed_offsets = {offset}
        partner = self.mirror_partner_offset(offset)
        if partner is not None and partner != offset:
            self.image.data[partner] = self.image.data[offset]
            changed_offsets.add(partner)
        return changed_offsets

    def refresh_offsets(self, offsets: set[int]) -> None:
        line_numbers = sorted({offset // BYTES_PER_LINE + 1 for offset in offsets})
        for line_no in line_numbers:
            self.replace_editor_line(line_no)

    def on_editor_keypress(self, event: tk.Event) -> str | None:
        if not self.image:
            return None
        if bool(event.state & 0x4):
            return None
        if event.keysym in {"Left", "Right", "Up", "Down", "Home", "End", "Prior", "Next"}:
            return None

        target = self.target_from_index(self.editor.index(tk.INSERT), snap=True)
        if target is None:
            return "break"
        if event.keysym == "BackSpace":
            self.set_insert_target(self.advance_target(target, -1))
            return "break"
        if event.keysym in {"Delete", "Tab"}:
            self.set_insert_target(self.advance_target(target, 1))
            return "break"
        if target.region == "hex" and len(event.char) == 1 and event.char.upper() in "0123456789ABCDEF":
            self.apply_hex_edit(target, event.char.upper())
            return "break"
        if target.region == "ascii" and len(event.char) == 1 and event.char.isprintable():
            self.image.data[target.offset] = ord(event.char)
            self.refresh_offsets(self.apply_mirror_link(target.offset))
            self.set_insert_target(self.advance_target(target, 1))
            return "break"
        if len(event.char) == 1 and event.char.isprintable():
            return "break"
        return None

    def apply_hex_edit(self, target: EditTarget, hex_char: str) -> None:
        assert self.image is not None
        old_value = self.image.data[target.offset]
        nibble_value = int(hex_char, 16)
        if target.nibble == 0:
            self.image.data[target.offset] = (nibble_value << 4) | (old_value & 0x0F)
            next_target = EditTarget(target.offset, "hex", 1)
        else:
            self.image.data[target.offset] = (old_value & 0xF0) | nibble_value
            next_target = EditTarget(min(len(self.image.data) - 1, target.offset + 1), "hex", 0)
        self.refresh_offsets(self.apply_mirror_link(target.offset))
        self.set_insert_target(next_target)

    def replace_editor_line(self, line_no: int) -> None:
        assert self.image is not None
        line_text = format_editor_line(self.image.data, self.image.base_address, line_no - 1)
        self.editor.delete(f"{line_no}.0", f"{line_no}.end")
        self.editor.insert(f"{line_no}.0", line_text)

    def snap_cursor(self, _event: tk.Event | None = None) -> None:
        if not self.image:
            return
        target = self.target_from_index(self.editor.index(tk.INSERT), snap=True)
        if target:
            self.set_insert_target(target)

    def target_from_index(self, index: str, snap: bool = False) -> EditTarget | None:
        if not self.image:
            return None
        line_no, column = self.parse_index(index)
        line_index = line_no - 1
        line_offset = line_index * BYTES_PER_LINE
        if line_offset >= len(self.image.data):
            return None
        bytes_in_line = min(BYTES_PER_LINE, len(self.image.data) - line_offset)

        for byte_in_line in range(bytes_in_line):
            start_col = hex_cell_start_column(byte_in_line)
            if start_col <= column < start_col + 2:
                return EditTarget(line_offset + byte_in_line, "hex", column - start_col)
            next_start = hex_cell_start_column(byte_in_line + 1) if byte_in_line + 1 < bytes_in_line else EDITOR_ASCII_START
            if start_col + 2 <= column < next_start:
                if snap and byte_in_line + 1 < bytes_in_line:
                    return EditTarget(line_offset + byte_in_line + 1, "hex", 0)
                if snap:
                    return EditTarget(line_offset + byte_in_line, "hex", 1)
                return None

        ascii_end = EDITOR_ASCII_START + bytes_in_line
        if EDITOR_ASCII_START <= column < ascii_end:
            return EditTarget(line_offset + column - EDITOR_ASCII_START, "ascii")

        if not snap:
            return None
        if column < EDITOR_ASCII_START:
            return EditTarget(line_offset, "hex", 0)
        return EditTarget(line_offset + bytes_in_line - 1, "ascii")

    def advance_target(self, target: EditTarget, step: int) -> EditTarget:
        assert self.image is not None
        if target.region == "hex":
            if step > 0:
                if target.nibble == 0:
                    return EditTarget(target.offset, "hex", 1)
                return EditTarget(min(len(self.image.data) - 1, target.offset + 1), "hex", 0)
            if target.nibble == 1:
                return EditTarget(target.offset, "hex", 0)
            return EditTarget(max(0, target.offset - 1), "hex", 1)
        return EditTarget(min(max(target.offset + step, 0), len(self.image.data) - 1), "ascii")

    def set_insert_target(self, target: EditTarget) -> None:
        index = self.index_from_target(target)
        self.editor.mark_set(tk.INSERT, index)
        self.editor.see(index)

    @staticmethod
    def index_from_target(target: EditTarget) -> str:
        line_no = target.offset // BYTES_PER_LINE + 1
        byte_in_line = target.offset % BYTES_PER_LINE
        column = hex_cell_start_column(byte_in_line) + target.nibble if target.region == "hex" else EDITOR_ASCII_START + byte_in_line
        return f"{line_no}.{column}"

    @staticmethod
    def parse_index(index: str) -> tuple[int, int]:
        line_text, column_text = index.split(".")
        return int(line_text), int(column_text)

    def jump_to_address(self, _event: tk.Event | None = None) -> None:
        if not self.image:
            messagebox.showinfo("提示", "请先打开文件。")
            return
        raw = self.jump_text.get().strip().replace(" ", "").replace("_", "")
        if raw.lower().startswith("0x"):
            raw = raw[2:]
        try:
            address = int(raw, 16)
        except ValueError:
            messagebox.showerror("跳转失败", "请输入有效的十六进制地址。")
            return
        if self.image.base_address <= address <= self.image.end_address:
            offset = address - self.image.base_address
        elif 0 <= address < len(self.image.data):
            offset = address
            address = self.image.base_address + offset
        else:
            messagebox.showerror("跳转失败", f"地址不在范围内: 0x{self.image.base_address:X} - 0x{self.image.end_address:X}")
            return
        self.set_insert_target(EditTarget(offset, "hex", 0))
        self.status_text.set(f"已跳转到 0x{address:X}")

    def search_hex(self, _event: tk.Event | None = None) -> None:
        if not self.image:
            messagebox.showinfo("提示", "请先打开文件。")
            return
        try:
            needle = parse_hex_search(self.search_text.get())
        except ValueError as exc:
            messagebox.showerror("搜索失败", str(exc))
            return
        start = self.last_search_offset + 1
        found = bytes(self.image.data).find(needle, start)
        if found < 0 and start > 0:
            found = bytes(self.image.data).find(needle, 0)
        if found < 0:
            self.editor.tag_remove("search_match", "1.0", tk.END)
            self.status_text.set("未找到搜索内容。")
            return
        self.last_search_offset = found
        self.highlight_search(found, len(needle))
        self.set_insert_target(EditTarget(found, "hex", 0))
        self.status_text.set(f"找到: 0x{self.image.base_address + found:X}")

    def highlight_search(self, offset: int, length: int) -> None:
        self.editor.tag_remove("search_match", "1.0", tk.END)
        for item_offset in range(offset, offset + length):
            line_no = item_offset // BYTES_PER_LINE + 1
            byte_in_line = item_offset % BYTES_PER_LINE
            start_col = hex_cell_start_column(byte_in_line)
            self.editor.tag_add("search_match", f"{line_no}.{start_col}", f"{line_no}.{start_col + 2}")


def main() -> None:
    root = tk.Tk()
    LineChecksumToolApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
