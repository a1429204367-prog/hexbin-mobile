from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import dataclass

import hexbin_core as core


BYTES_PER_LINE = 16


@dataclass(frozen=True)
class ParameterDifferenceRow:
    start_address: int
    left_values: tuple[int | None, ...]
    right_values: tuple[int | None, ...]
    parameter_difference_count: int
    checksum_difference_count: int
    left_only_count: int
    right_only_count: int


@dataclass(frozen=True)
class ParameterComparison:
    rows: tuple[ParameterDifferenceRow, ...]
    matching_count: int
    parameter_difference_count: int
    checksum_difference_count: int
    left_only_count: int
    right_only_count: int

    @property
    def total_difference_count(self) -> int:
        return self.parameter_difference_count + self.checksum_difference_count


def _base_address(parameter_file) -> int:
    return getattr(parameter_file, "display_base_address", parameter_file.min_address)


def _is_dense(parameter_file) -> bool:
    data_size = len(parameter_file.current_full_bin)
    present_offsets = parameter_file.present_offsets
    if len(present_offsets) != data_size:
        return False
    if data_size == 0:
        return True
    if isinstance(present_offsets, range):
        return present_offsets == range(data_size)
    return min(present_offsets) == 0 and max(present_offsets) == data_size - 1


def _iter_bytes(parameter_file):
    data = parameter_file.current_full_bin
    present_offsets = parameter_file.present_offsets
    offsets = range(len(data)) if _is_dense(parameter_file) else sorted(present_offsets)
    base_address = _base_address(parameter_file)
    for offset in offsets:
        if 0 <= offset < len(data):
            yield base_address + offset, data[offset]


def value_at(parameter_file, address: int) -> int | None:
    offset = address - _base_address(parameter_file)
    if offset < 0 or offset >= len(parameter_file.current_full_bin):
        return None
    if offset not in parameter_file.present_offsets:
        return None
    return parameter_file.current_full_bin[offset]


def checksum_display_addresses(parameter_file) -> set[int]:
    display_delta = _base_address(parameter_file) - parameter_file.min_address
    return {
        address + display_delta
        for region in parameter_file.checksum_regions
        for address in region.checksum_addresses
    }


def compare_parameter_files(left_file, right_file) -> ParameterComparison:
    checksum_addresses = checksum_display_addresses(left_file) | checksum_display_addresses(right_file)
    row_stats: dict[int, list[int]] = {}
    matching_count = 0
    parameter_difference_count = 0
    checksum_difference_count = 0
    left_only_count = 0
    right_only_count = 0

    left_iterator = iter(_iter_bytes(left_file))
    right_iterator = iter(_iter_bytes(right_file))
    left_item = next(left_iterator, None)
    right_item = next(right_iterator, None)

    while left_item is not None or right_item is not None:
        if right_item is None or (left_item is not None and left_item[0] < right_item[0]):
            address = left_item[0]
            left_only_count += 1
            side_index = 2
            left_item = next(left_iterator, None)
        elif left_item is None or right_item[0] < left_item[0]:
            address = right_item[0]
            right_only_count += 1
            side_index = 3
            right_item = next(right_iterator, None)
        else:
            address = left_item[0]
            if left_item[1] == right_item[1]:
                matching_count += 1
                left_item = next(left_iterator, None)
                right_item = next(right_iterator, None)
                continue
            side_index = None
            left_item = next(left_iterator, None)
            right_item = next(right_iterator, None)

        row_start = address & ~(BYTES_PER_LINE - 1)
        stats = row_stats.setdefault(row_start, [0, 0, 0, 0])
        if address in checksum_addresses:
            checksum_difference_count += 1
            stats[1] += 1
        else:
            parameter_difference_count += 1
            stats[0] += 1
        if side_index is not None:
            stats[side_index] += 1

    rows = tuple(
        ParameterDifferenceRow(
            start_address=row_start,
            left_values=tuple(value_at(left_file, row_start + index) for index in range(BYTES_PER_LINE)),
            right_values=tuple(value_at(right_file, row_start + index) for index in range(BYTES_PER_LINE)),
            parameter_difference_count=stats[0],
            checksum_difference_count=stats[1],
            left_only_count=stats[2],
            right_only_count=stats[3],
        )
        for row_start, stats in sorted(row_stats.items())
    )
    return ParameterComparison(
        rows=rows,
        matching_count=matching_count,
        parameter_difference_count=parameter_difference_count,
        checksum_difference_count=checksum_difference_count,
        left_only_count=left_only_count,
        right_only_count=right_only_count,
    )


def build_shared_line_starts(left_file, right_file) -> tuple[int, ...]:
    line_starts: set[int] = set()
    for parameter_file in (left_file, right_file):
        base_address = _base_address(parameter_file)
        data = parameter_file.current_full_bin
        present_offsets = parameter_file.present_offsets
        if not present_offsets:
            continue
        if _is_dense(parameter_file):
            first_line = base_address & ~(BYTES_PER_LINE - 1)
            last_line = (base_address + len(data) - 1) & ~(BYTES_PER_LINE - 1)
            line_starts.update(range(first_line, last_line + BYTES_PER_LINE, BYTES_PER_LINE))
            continue
        line_starts.update(
            (base_address + offset) & ~(BYTES_PER_LINE - 1)
            for offset in present_offsets
            if 0 <= offset < len(data)
        )
    return tuple(sorted(line_starts))


def difference_addresses(comparison: ParameterComparison) -> tuple[int, ...]:
    return tuple(
        row.start_address + index
        for row in comparison.rows
        for index, (left_value, right_value) in enumerate(zip(row.left_values, row.right_values))
        if left_value != right_value
    )


def build_page(left_file, right_file, line_starts: tuple[int, ...], start_address: int, count: int) -> dict:
    index = bisect_left(line_starts, start_address & ~(BYTES_PER_LINE - 1))
    rows = []
    checksum_addresses = checksum_display_addresses(left_file) | checksum_display_addresses(right_file)
    for line_start in line_starts[index : index + count]:
        left_values = [value_at(left_file, line_start + offset) for offset in range(BYTES_PER_LINE)]
        right_values = [value_at(right_file, line_start + offset) for offset in range(BYTES_PER_LINE)]
        diff_types = []
        for offset, (left_value, right_value) in enumerate(zip(left_values, right_values)):
            address = line_start + offset
            if left_value == right_value:
                diff_types.append(None)
            elif left_value is None or right_value is None:
                diff_types.append("missing")
            elif address in checksum_addresses:
                diff_types.append("checksum")
            else:
                diff_types.append("parameter")
        rows.append({
            "address": line_start,
            "left": left_values,
            "right": right_values,
            "diffTypes": diff_types,
        })
    return {"index": index, "total": len(line_starts), "rows": rows}


def snapshot(comparison: ParameterComparison) -> dict:
    return {
        "matchingCount": comparison.matching_count,
        "parameterDifferenceCount": comparison.parameter_difference_count,
        "checksumDifferenceCount": comparison.checksum_difference_count,
        "leftOnlyCount": comparison.left_only_count,
        "rightOnlyCount": comparison.right_only_count,
        "totalDifferenceCount": comparison.total_difference_count,
        "differenceAddresses": list(difference_addresses(comparison)),
    }
