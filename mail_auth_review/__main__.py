"""Command line entry point for local header inspection."""

import argparse
import sys
from pathlib import Path

from .headers import HeaderError, read_auth_fields
from .report import render_json, render_text, review


def _server(value: str) -> str:
    if not value.strip() or not value.isascii() or not value.isprintable():
        raise argparse.ArgumentTypeError(
            "expected a nonblank printable ASCII authserv-id"
        )
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mail-auth-review",
        description="Review SPF, DKIM, and DMARC claims in saved email headers offline.",
        allow_abbrev=False,
    )
    parser.add_argument("input", help="saved headers or .eml path; use - for stdin")
    parser.add_argument(
        "--server",
        action="append",
        type=_server,
        default=[],
        metavar="ID",
        help="select an exact authserv-id, ignoring ASCII case (repeatable)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    args = parser.parse_args(argv)
    try:
        if args.input == "-":
            fields = read_auth_fields(sys.stdin.buffer)
        else:
            with Path(args.input).open("rb") as source:
                fields = read_auth_fields(source)
    except (HeaderError, OSError) as error:
        print(f"mail-auth-review: {error}", file=sys.stderr)
        return 1

    report = review(fields, args.server)
    print(render_json(report) if args.format == "json" else render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
