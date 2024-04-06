from io import BytesIO

import pytest

from mail_auth_review.headers import (
    MAX_FIELDS,
    MAX_HEADER_BYTES,
    MAX_LINE_BYTES,
    AuthField,
    HeaderError,
    read_auth_fields,
)


def test_collects_only_exact_field_name_and_preserves_order_and_folding():
    source = BytesIO(
        b"From: robot@sender.example\r\n"
        b"ARC-Authentication-Results: 1; arc.example\r\n"
        b"aUtHeNtIcAtIoN-rEsUlTs: mx.first.example;\r\n"
        b"\tspf=pass smtp.mailfrom=sender.example\r\n"
        b"Authentication-Results: mx.second.example; none\r\n"
        b"\r\nAuthentication-Results: body.example; spf=pass\xff"
    )
    assert read_auth_fields(source) == [
        AuthField(3, b"mx.first.example;\tspf=pass smtp.mailfrom=sender.example"),
        AuthField(5, b"mx.second.example; none"),
    ]
    assert source.read().startswith(b"Authentication-Results: body.example")


def test_header_only_input_can_end_without_newline():
    assert read_auth_fields(
        BytesIO(b"Subject: synthetic\nAuthentication-Results: x.example")
    ) == [AuthField(2, b"x.example")]


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b" continuation\n", "line 1: continuation without a field"),
        (b"Subject : synthetic\n", "line 1: invalid header field"),
        (b"not a header\n", "line 1: invalid header field"),
        (b"Subject: synthetic\x00\n", "line 1: control byte"),
        (b"Subject: synthetic\r", "line 1: control byte"),
        (b"X:" + b"x" * (MAX_LINE_BYTES - 2) + b"\n", "line 1: exceeds"),
        (b"X:\n" * (MAX_FIELDS + 1), f"exceeds {MAX_FIELDS} fields"),
        (
            (b"X:" + b"x" * (MAX_LINE_BYTES - 3) + b"\n") * 8 + b"\n",
            "header block exceeds",
        ),
    ],
)
def test_rejects_malformed_or_oversize_header_blocks(data, message):
    with pytest.raises(HeaderError, match=message):
        read_auth_fields(BytesIO(data))


def test_exact_line_and_header_byte_limits_accept_eof():
    line = b"X:" + b"x" * (MAX_LINE_BYTES - 3) + b"\n"
    assert len(line) == MAX_LINE_BYTES
    assert len(line * 8) == MAX_HEADER_BYTES
    assert read_auth_fields(BytesIO(line * 8)) == []
