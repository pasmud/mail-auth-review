"""Parse reported Authentication-Results claims without validating them."""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from itertools import chain
from typing import Literal

from .headers import AuthField

MAX_CLAUSES = 128
METHODS = frozenset({"spf", "dkim", "dmarc"})
Status = Literal["parsed", "partial", "none", "invalid", "unsupported-version"]

_KEYWORD = r"[A-Za-z0-9][A-Za-z0-9_-]*"
_TOKEN = r"[A-Za-z0-9!#$%&'*+.^_`{|}~-]+"
_QUOTED = r'"(?:[^"\\]|\\.)*"'
_PREFIX = re.compile(
    rf"[ \t]*(?P<server>{_QUOTED}|{_TOKEN})(?:[ \t]+(?P<version>[0-9]+))?[ \t]*"
)
_RESULT = re.compile(
    rf"[ \t]*(?P<method>{_KEYWORD})(?:[ \t]*/[ \t]*(?P<version>[0-9]+))?"
    rf"[ \t]*=[ \t]*(?P<result>{_KEYWORD})(?=[ \t]|$)"
)
_ASSIGNMENT = re.compile(
    rf"[ \t]+(?:(?P<ptype>{_KEYWORD})[ \t]*\.[ \t]*(?P<property>{_KEYWORD})|(?P<reason>(?i:reason)))"
    rf'[ \t]*=[ \t]*(?P<value>{_QUOTED}|[^ \t"=\\]+)(?=[ \t]|$)'
)


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    message: str
    clause: int | None = None


@dataclass(frozen=True, slots=True)
class Property:
    name: str
    value: str


@dataclass(frozen=True, slots=True)
class Claim:
    method: str
    result: str
    method_version: str
    reason: str | None
    properties: tuple[Property, ...]


@dataclass(frozen=True, slots=True)
class ResultField:
    line: int
    authserv_id: str | None
    version: str | None
    status: Status
    claims: tuple[Claim, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()


class _SyntaxError(ValueError):
    pass


def _clauses(text: str) -> Iterator[str]:
    """Split only at top-level semicolons and replace each comment with space."""
    part: list[str] = []
    depth = 0
    quoted = escaped = False
    for char in text:
        if depth:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
        elif quoted:
            part.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == "(":
            part.append(" ")
            depth = 1
        elif char == ")":
            raise _SyntaxError("unexpected closing parenthesis")
        elif char == ";":
            yield "".join(part)
            part.clear()
        else:
            part.append(char)
            quoted = char == '"'
    if depth:
        raise _SyntaxError("unterminated comment")
    if quoted:
        raise _SyntaxError("unterminated quoted string")
    yield "".join(part)


def _unquote(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value[1:-1]) if value.startswith('"') else value


def _version(value: str | None) -> str:
    return "1" if value is None else value.lstrip("0") or "0"


def _parse_claim(clause: str) -> Claim:
    match = _RESULT.match(clause)
    if not match:
        raise _SyntaxError("expected a method=result pair")
    method = match["method"].lower()
    result, version = match["result"].lower(), _version(match["version"])
    reason = None
    properties: list[Property] = []
    end = len(clause.rstrip(" \t"))
    pos = match.end()
    while pos < end:
        assignment = _ASSIGNMENT.match(clause, pos)
        if not assignment:
            raise _SyntaxError("expected reason=value or property-type.name=value")
        value = assignment["value"]
        if assignment["reason"]:
            if reason is not None or properties:
                raise _SyntaxError("reason must appear at most once, before properties")
            if not value.startswith('"') and not re.fullmatch(_TOKEN, value):
                raise _SyntaxError("reason must be a token or quoted string")
            reason = _unquote(value)
        else:
            name = f"{assignment['ptype']}.{assignment['property']}".lower()
            properties.append(Property(name, _unquote(value)))
        pos = assignment.end()
    return Claim(method, result, version, reason, tuple(properties))


def parse_field(field: AuthField) -> ResultField:
    """Keep intact claims from recoverable clauses; quarantine ambiguous fields."""
    line, server, version = field.line, None, None

    def invalid(code: str, message: str, clause: int | None = None) -> ResultField:
        return ResultField(
            line,
            server,
            version,
            "invalid",
            diagnostics=(Diagnostic(code, message, clause),),
        )

    try:
        clauses = _clauses(field.value.decode("ascii"))
        prefix = _PREFIX.fullmatch(next(clauses))
        if not prefix:
            return invalid(
                "invalid-authserv", "expected an authserv-id and optional version"
            )
        candidate = _unquote(prefix["server"])
        if not candidate.strip() or not candidate.isprintable():
            return invalid(
                "invalid-authserv", "authserv-id must be printable and nonblank"
            )
        server, version = candidate, _version(prefix["version"])
        first = next(clauses, None)
        if first is None:
            return invalid(
                "missing-results", "expected a semicolon and a result clause"
            )
        if version != "1":
            return ResultField(
                line,
                server,
                version,
                "unsupported-version",
                diagnostics=(
                    Diagnostic(
                        "unsupported-version", "only authres version 1 is interpreted"
                    ),
                ),
            )

        if first.strip(" \t").lower() == "none":
            if next(clauses, None) is not None:
                return invalid("mixed-none", "none must be the only result clause", 1)
            return ResultField(line, server, version, "none")

        claims: list[Claim] = []
        diagnostics: list[Diagnostic] = []
        any_valid = False
        for number, clause in enumerate(chain((first,), clauses), 1):
            if number > MAX_CLAUSES:
                return invalid(
                    "too-many-clauses", f"field exceeds {MAX_CLAUSES} result clauses"
                )
            if clause.strip(" \t").lower() == "none":
                return invalid(
                    "mixed-none", "none must be the only result clause", number
                )
            try:
                claim = _parse_claim(clause)
            except _SyntaxError as error:
                diagnostics.append(Diagnostic("invalid-clause", str(error), number))
            else:
                any_valid = True
                if claim.method in METHODS:
                    claims.append(claim)
        status: Status = (
            "invalid" if not any_valid else "partial" if diagnostics else "parsed"
        )
        return ResultField(
            line, server, version, status, tuple(claims), tuple(diagnostics)
        )
    except UnicodeDecodeError:
        return invalid("non-ascii", "Authentication-Results must be ASCII")
    except _SyntaxError as error:
        return invalid("invalid-structure", str(error))
