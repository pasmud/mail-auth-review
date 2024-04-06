"""Read a bounded RFC-style header block without processing the message body."""

import re
from dataclasses import dataclass
from typing import BinaryIO

MAX_HEADER_BYTES = 65_536
MAX_LINE_BYTES = 8_192
MAX_FIELDS = 256

_FIELD_NAME = re.compile(rb"[!-9;-~]+")
_CONTROL = re.compile(rb"[\x00-\x08\x0a-\x1f\x7f]")


class HeaderError(ValueError):
    """The header block is malformed or exceeds an input limit."""


@dataclass(frozen=True, slots=True)
class AuthField:
    """An unfolded Authentication-Results value and its starting line."""

    line: int
    value: bytes


def read_auth_fields(source: BinaryIO) -> list[AuthField]:
    """Read LF or CRLF lines through the first empty line, or through EOF."""
    fields: list[AuthField] = []
    total = count = line_number = auth_line = 0
    parts: list[bytes] = []

    while True:
        raw = source.readline(min(MAX_LINE_BYTES, MAX_HEADER_BYTES - total) + 1)
        if not raw:
            break
        line_number += 1
        total += len(raw)
        if len(raw) > MAX_LINE_BYTES:
            raise HeaderError(f"line {line_number}: exceeds {MAX_LINE_BYTES} bytes")
        if total > MAX_HEADER_BYTES:
            raise HeaderError(f"header block exceeds {MAX_HEADER_BYTES} bytes")

        line = raw
        if line.endswith(b"\n"):
            line = line[:-1].removesuffix(b"\r")
        if not line:
            break
        if _CONTROL.search(line):
            raise HeaderError(f"line {line_number}: control byte in header")
        if line.startswith((b" ", b"\t")):
            if not count:
                raise HeaderError(f"line {line_number}: continuation without a field")
            if auth_line:
                parts.append(line)
            continue

        if auth_line:
            fields.append(AuthField(auth_line, b"".join(parts).strip(b" \t")))
            auth_line = 0
        name, separator, value = line.partition(b":")
        if not separator or not _FIELD_NAME.fullmatch(name):
            raise HeaderError(
                f"line {line_number}: invalid header field name or missing colon"
            )
        count += 1
        if count > MAX_FIELDS:
            raise HeaderError(f"header block exceeds {MAX_FIELDS} fields")
        if name.lower() == b"authentication-results":
            auth_line, parts = line_number, [value]

    if auth_line:
        fields.append(AuthField(auth_line, b"".join(parts).strip(b" \t")))
    return fields
