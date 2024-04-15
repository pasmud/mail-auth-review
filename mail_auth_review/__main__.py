"""Command line entry point for local header inspection."""

import argparse
import sys
from pathlib import Path

from .headers import HeaderError, read_auth_fields
from .results import parse_field


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="saved headers or .eml path; use - for stdin")
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

    print("Reported Authentication-Results only; authenticity not verified.")
    for raw_field in fields:
        field = parse_field(raw_field)
        print(f"Line {field.line}: {field.authserv_id!r} [{field.status}]")
        for claim in field.claims:
            print(f"  {claim.method}={claim.result}")
        for issue in field.diagnostics:
            print(f"  {issue.code}: {issue.message}")
    if not fields:
        print("No Authentication-Results fields found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
