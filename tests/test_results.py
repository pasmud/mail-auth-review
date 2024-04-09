import pytest

from mail_auth_review.headers import AuthField
from mail_auth_review.results import MAX_CLAUSES, Claim, Property, parse_field


def parse(value: bytes):
    return parse_field(AuthField(7, value))


def test_comments_quotes_versions_and_repeated_properties():
    field = parse(
        rb'(outer (inner"\); pretend=pass) note) "MX; Lab" (version) 01;'
        rb' DKIM (version) / 002 = PASS Reason="quoted \"note\"; (kept)"'
        rb" Header (separator) . D=sender.example header.d=second.example;"
        rb" SPF=SoftFail smtp.mailfrom=robot@sender.example; DMARC=Fail"
    )
    assert (field.line, field.authserv_id, field.version, field.status) == (
        7,
        "MX; Lab",
        "1",
        "parsed",
    )
    assert field.claims == (
        Claim(
            "dkim",
            "pass",
            "2",
            'quoted "note"; (kept)',
            (
                Property("header.d", "sender.example"),
                Property("header.d", "second.example"),
            ),
        ),
        Claim(
            "spf",
            "softfail",
            "1",
            None,
            (Property("smtp.mailfrom", "robot@sender.example"),),
        ),
        Claim("dmarc", "fail", "1", None, ()),
    )
    assert not field.diagnostics


def test_comments_are_boundaries_not_token_glue():
    field = parse(b"mx.example; sp(comment)f=pass; dmarc=pa(comment)ss; dkim=pass")
    assert field.status == "partial"
    assert [claim.method for claim in field.claims] == ["dkim"]
    assert [issue.clause for issue in field.diagnostics] == [1, 2]


def test_quoted_local_part_is_preserved_as_part_of_the_mailbox():
    field = parse(
        rb'mx.example; spf=pass smtp.mailfrom="ops; \"night\""@Sender.Example'
        rb' smtp.helo="relay.example"; dmarc=fail header.from=other.example'
    )
    assert field.status == "parsed"
    assert field.claims == (
        Claim(
            "spf",
            "pass",
            "1",
            None,
            (
                Property("smtp.mailfrom", r'"ops; \"night\""@Sender.Example'),
                Property("smtp.helo", "relay.example"),
            ),
        ),
        Claim("dmarc", "fail", "1", None, (Property("header.from", "other.example"),)),
    )


@pytest.mark.parametrize(
    "assignment",
    [
        b'smtp.mailfrom="ops"@',
        b'smtp.mailfrom="ops"@sender..example',
        b'smtp.mailfrom="ops"(comment)@sender.example',
        b'reason="ops"@sender.example',
    ],
)
def test_malformed_or_misplaced_composite_value_is_only_a_clause_error(assignment):
    field = parse(b"mx.example; spf=pass " + assignment + b"; dmarc=fail")
    assert field.status == "partial"
    assert field.claims == (Claim("dmarc", "fail", "1", None, ()),)
    assert [(issue.code, issue.clause) for issue in field.diagnostics] == [
        ("invalid-clause", 1)
    ]


def test_malformed_clause_recovery_preserves_order_and_drops_the_entire_bad_claim():
    field = parse(
        b'mx.example; spf=pass; dkim=pass header.d=; ; dkim=fail reason="";'
        b' dmarc=pass header.from="sender.example"'
    )
    assert field.status == "partial"
    assert [(claim.method, claim.result) for claim in field.claims] == [
        ("spf", "pass"),
        ("dkim", "fail"),
        ("dmarc", "pass"),
    ]
    assert [(issue.code, issue.clause) for issue in field.diagnostics] == [
        ("invalid-clause", 2),
        ("invalid-clause", 3),
    ]


@pytest.mark.parametrize(
    ("value", "code", "server"),
    [
        (b"; spf=pass", "invalid-authserv", None),
        (b'"mx.example"1; spf=pass', "invalid-authserv", None),
        (b'"   "; spf=pass', "invalid-authserv", None),
        (b"mx.example extra; spf=pass", "invalid-authserv", None),
        (b"mx.example", "missing-results", "mx.example"),
        (b"mx.example; (comment only)", "invalid-clause", "mx.example"),
        (b"mx.example; spf=pass; none", "mixed-none", "mx.example"),
        (b"mx.example; none; spf=pass", "mixed-none", "mx.example"),
        (b"mx.example; spf=pass; dkim=fail (oops", "invalid-structure", "mx.example"),
        (
            b'mx.example; spf=pass; dkim=fail reason="oops',
            "invalid-structure",
            "mx.example",
        ),
        (b"mx.example; spf=pass)", "invalid-structure", "mx.example"),
        (b"(unclosed; mx.example; spf=pass", "invalid-structure", None),
        (b"mx.example; spf=pass \xff", "non-ascii", None),
        (b"mx.example; spf=pass header.x=x reason=a", "invalid-clause", "mx.example"),
        (b'mx.example; spf=pass reason="" reason=b', "invalid-clause", "mx.example"),
    ],
)
def test_invalid_fields_never_yield_claims(value, code, server):
    field = parse(value)
    assert field.status == "invalid"
    assert field.authserv_id == server
    assert not field.claims
    assert [issue.code for issue in field.diagnostics] == [code]


def test_none_untracked_and_unsupported_versions_have_distinct_statuses():
    none = parse(b"mx.example; (no checks) NoNe")
    assert (none.status, none.claims, none.diagnostics) == ("none", (), ())
    untracked = parse(b"mx.example; auth=pass smtp.auth=robot@sender.example")
    assert (untracked.status, untracked.claims, untracked.diagnostics) == (
        "parsed",
        (),
        (),
    )
    unsupported = parse(b"mx.example 9; spf=pass")
    assert (unsupported.status, unsupported.version, unsupported.claims) == (
        "unsupported-version",
        "9",
        (),
    )
    assert unsupported.diagnostics[0].code == "unsupported-version"


def test_many_clauses_are_bounded_per_header():
    value = b"mx.example" + b"; dkim=pass" * MAX_CLAUSES
    assert len(parse(value).claims) == MAX_CLAUSES
    overflow = parse(value + b"; spf=pass")
    assert not overflow.claims
    assert overflow.diagnostics[0].code == "too-many-clauses"
