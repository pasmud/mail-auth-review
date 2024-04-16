"""Select reporting IDs and render deterministic offline review output."""

import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass

from .headers import AuthField
from .results import ResultField, parse_field

NOTICE = "Reported claims only; this review does not verify authenticity or who wrote a field."


@dataclass(frozen=True, slots=True)
class Report:
    schema_version: int
    notice: str
    server_filter: tuple[str, ...]
    total_fields: int
    excluded_fields: int
    fields: tuple[ResultField, ...]


def review(fields: Iterable[AuthField], servers: Iterable[str] = ()) -> Report:
    """Filter by exact ASCII case-insensitive ID; always retain unattributed issues."""
    wanted = frozenset(server.lower() for server in servers)
    shown: list[ResultField] = []
    excluded = 0
    for raw_field in fields:
        field = parse_field(raw_field)
        if (
            wanted
            and field.authserv_id is not None
            and field.authserv_id.lower() not in wanted
        ):
            excluded += 1
        else:
            shown.append(field)
    return Report(
        1, NOTICE, tuple(sorted(wanted)), len(shown) + excluded, excluded, tuple(shown)
    )


def render_json(report: Report) -> str:
    return json.dumps(asdict(report), ensure_ascii=True, indent=2)


def _preamble(report: Report) -> list[str]:
    lines = [
        report.notice,
        (
            f"Authentication-Results: {report.total_fields} found, "
            f"{len(report.fields)} shown, {report.excluded_fields} excluded."
        ),
    ]
    if report.server_filter:
        lines.append(
            "Server filter: " + ", ".join(map(json.dumps, report.server_filter))
        )
    if not report.total_fields:
        lines.append("No Authentication-Results fields found.")
    elif report.server_filter and not any(
        field.authserv_id is not None for field in report.fields
    ):
        lines.append("No fields matched the reporting server filter.")
    return lines


def render_summary(report: Report) -> str:
    """Count reported claims by visible reporter, without inferring a verdict."""
    lines = _preamble(report)
    if not report.fields:
        return "\n".join(lines)

    groups: dict[str | None, list[ResultField]] = defaultdict(list)
    for field in report.fields:
        reporter = field.authserv_id
        groups[None if reporter is None else reporter.lower()].append(field)

    lines.append("Reporter summary (counts of reported method=result claims):")
    for reporter, fields in groups.items():
        label = (
            "unattributed"
            if reporter is None
            else f"authserv-id={json.dumps(reporter)}"
        )
        locations = ",".join(str(field.line) for field in fields)
        counts = Counter(
            (claim.method, claim.result) for field in fields for claim in field.claims
        )
        outcomes = ", ".join(
            f"{method}={result} x{count}"
            for (method, result), count in sorted(counts.items())
        )
        diagnosed = sum(bool(field.diagnostics) for field in fields)
        lines.append(
            f"  {label} lines={locations}: {outcomes or 'no tracked claims'}; "
            f"fields with diagnostics={diagnosed}"
        )
    return "\n".join(lines)


def render_text(report: Report) -> str:
    lines = _preamble(report)
    for field in report.fields:
        label = (
            "unattributed"
            if field.authserv_id is None
            else f"authserv-id={json.dumps(field.authserv_id)} version={field.version}"
        )
        lines.append(f"Line {field.line}: {label} [{field.status}]")
        for claim in field.claims:
            suffix = "" if claim.method_version == "1" else f"/{claim.method_version}"
            parts = [f"  {claim.method}{suffix}={claim.result}"]
            if claim.reason is not None:
                parts.append(f"reason={json.dumps(claim.reason)}")
            parts.extend(
                f"{prop.name}={json.dumps(prop.value)}" for prop in claim.properties
            )
            lines.append(" ".join(parts))
        if not field.claims and field.status in {"parsed", "partial"}:
            lines.append("  No SPF, DKIM, or DMARC claims in accepted clauses.")
        for issue in field.diagnostics:
            location = "" if issue.clause is None else f" (clause {issue.clause})"
            lines.append(f"  {issue.code}{location}: {issue.message}")
    return "\n".join(lines)
