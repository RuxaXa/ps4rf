"""Generic measurements over a bounded snapshot.

Only bytes the snapshot already returned are inspected: no scan, no second read.
Which cells matter is decided by the experiment, not here.
"""
from __future__ import annotations

from tools.experiments.device import Snapshot

TOKEN_LEN = 8


def find_token(data: bytes, token: bytes) -> int:
    if len(token) != TOKEN_LEN:
        raise ValueError("token must be 8 bytes")
    return data.find(token)


def count_token(data: bytes, token: bytes) -> int:
    n, start = 0, 0
    while True:
        i = data.find(token, start)
        if i < 0:
            return n
        n += 1
        start = i + TOKEN_LEN


def token_in(snapshot: Snapshot, token: bytes, cells=None) -> tuple:
    hits = []
    for name, cell in snapshot.cells.items():
        if cells is not None and name not in cells:
            continue
        if cell.ok() and cell.data and find_token(cell.data, token) >= 0:
            hits.append(name)
    return tuple(hits)


def token_in_slice(snapshot: Snapshot, token: bytes, cells, offset: int, length: int) -> tuple:
    hits = []
    for name in cells:
        cell = snapshot.cells.get(name)
        if cell is None or not cell.ok() or not cell.data or len(cell.data) < offset:
            continue
        if find_token(cell.data[offset:offset + length], token) >= 0:
            hits.append(name)
    return tuple(hits)


def token_in_window_range(snapshot: Snapshot, token: bytes, cells_bases: dict,
                          start: int, end: int) -> tuple:
    """Cells whose bytes place ``token`` inside [start, end) of the *window*, using
    each cell's declared base offset. Recipe agnostic: no fixed offset is assumed."""
    hits = []
    for name, base in cells_bases.items():
        cell = snapshot.cells.get(name)
        if cell is None or not cell.ok() or not cell.data:
            continue
        for i in range(0, max(0, len(cell.data) - TOKEN_LEN + 1)):
            if cell.data[i:i + TOKEN_LEN] == token and start <= base + i < end:
                hits.append(name)
                break
    return tuple(hits)


def byte_diff(a: bytes, b: bytes) -> int:
    return sum(1 for x, y in zip(a, b) if x != y)


def popcount(data: bytes) -> int:
    return sum(bin(b).count("1") for b in data)


def word_delta(before: bytes, after: bytes) -> tuple:
    new = lost = 0
    for i in range(0, min(len(before), len(after)) - 7, 8):
        a = int.from_bytes(before[i:i + 8], "little")
        b = int.from_bytes(after[i:i + 8], "little")
        if a == 0 and b != 0:
            new += 1
        if a != 0 and b == 0:
            lost += 1
    return new, lost
