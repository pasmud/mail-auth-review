import json
import subprocess
import sys
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def cli(*args, data=b""):
    return subprocess.run(
        [sys.executable, "-m", "mail_auth_review", *map(str, args)],
        input=data,
        capture_output=True,
        check=False,
    )


def test_stable_json_for_file_and_stdin_with_exact_repeatable_filter(tmp_path):
    data = (
        b"Subject: synthetic\r\n"
        b"Authentication-Results: mx.lab.example.suffix; dmarc=fail\r\n"
        b"Authentication-Results: MX.Lab.Example; spf=pass\r\n"
        b"\tSMTP.MailFrom=robot@sender.example;\r\n"
        b"\tdkim=pass header.d=; dmarc=pass header.from=sender.example\r\n"
        b'Authentication-Results: "Lab Relay"; none\r\n'
        b"Authentication-Results: mx.lab.example.; spf=fail\r\n"
        b"Authentication-Results: ; dkim=pass\r\n"
        b"Authentication-Results: mx.lab.example; dkim=neutral\r\n"
        b"\r\nAuthentication-Results: MX.Lab.Example; spf=fail\r\n"
    )
    message = tmp_path / "synthetic message.eml"
    message.write_bytes(data)
    args = ("--format", "json", "--server", "mx.lab.example", "--server", "lab relay")
    file_result = cli(*args, message)
    stdin_result = cli(*args, "--server", "MX.LAB.EXAMPLE", "-", data=data)
    assert file_result.returncode == stdin_result.returncode == 0
    assert file_result.stderr == stdin_result.stderr == b""
    assert file_result.stdout == stdin_result.stdout
    result = json.loads(file_result.stdout)
    assert result["schema_version"] == 1
    assert "does not verify authenticity" in result["notice"]
    assert result["server_filter"] == ["lab relay", "mx.lab.example"]
    assert (result["total_fields"], result["excluded_fields"]) == (6, 2)
    assert [(f["line"], f["authserv_id"], f["status"]) for f in result["fields"]] == [
        (3, "MX.Lab.Example", "partial"),
        (6, "Lab Relay", "none"),
        (8, None, "invalid"),
        (9, "mx.lab.example", "parsed"),
    ]
    first = result["fields"][0]
    assert first["claims"][0] == {
        "method": "spf",
        "result": "pass",
        "method_version": "1",
        "reason": None,
        "properties": [{"name": "smtp.mailfrom", "value": "robot@sender.example"}],
    }
    assert [c["method"] for c in first["claims"]] == ["spf", "dmarc"]
    assert first["diagnostics"][0]["clause"] == 2
    assert not result["fields"][2]["claims"]


def test_text_escapes_quoted_values_and_labels_claims():
    result = cli(
        "-",
        data=b'Authentication-Results: mx.example; dkim/2=pass reason="sample;\tfold" header.d=sender.example',
    )
    assert result.returncode == 0
    assert result.stderr == b""
    assert result.stdout.decode().splitlines() == [
        "Reported claims only; this review does not verify authenticity or who wrote a field.",
        "Authentication-Results: 1 found, 1 shown, 0 excluded.",
        'Line 1: authserv-id="mx.example" version=1 [parsed]',
        '  dkim/2=pass reason="sample;\\tfold" header.d="sender.example"',
    ]


def test_no_fields_and_no_matching_fields_are_distinct():
    empty = cli("-", data=b"Subject: synthetic\n")
    no_match = cli(
        "--server",
        "elsewhere.example",
        "-",
        data=b"Authentication-Results: mx.example; none",
    )
    assert empty.returncode == no_match.returncode == 0
    assert b"No Authentication-Results fields found." in empty.stdout
    assert b"No fields matched the reporting server filter." in no_match.stdout


def test_summary_groups_reported_results_and_keeps_diagnostic_only_fields():
    result = cli(
        "--format",
        "summary",
        "-",
        data=(
            b"Authentication-Results: MX.Receiver.Example; spf=pass reason=example"
            b" smtp.mailfrom=robot@sender.example; dkim=pass header.d=; ; spf=fail\n"
            b"Authentication-Results: relay.example; spf=fail; dmarc=custom\n"
            b"Authentication-Results: mx.receiver.example; spf/2=PASS; dkim=fail\n"
            b"Authentication-Results: mx.receiver.example 2; spf=pass\n"
            b"Authentication-Results: ; spf=pass\n"
            b"Authentication-Results: idle.example; none\n"
        ),
    )
    assert result.returncode == 0
    assert result.stderr == b""
    assert result.stdout.decode().splitlines() == [
        "Reported claims only; this review does not verify authenticity or who wrote a field.",
        "Authentication-Results: 6 found, 6 shown, 0 excluded.",
        "Reporter summary (counts of reported method=result claims):",
        '  authserv-id="mx.receiver.example" lines=1,3,4: dkim=fail x1, spf=fail x1, '
        "spf=pass x2; fields with diagnostics=2",
        '  authserv-id="relay.example" lines=2: dmarc=custom x1, spf=fail x1; fields with diagnostics=0',
        "  unattributed lines=5: no tracked claims; fields with diagnostics=1",
        '  authserv-id="idle.example" lines=6: no tracked claims; fields with diagnostics=0',
    ]


def test_summary_counts_only_fields_shown_by_the_server_filter():
    result = cli(
        "--format",
        "summary",
        "--server",
        "LAB RELAY",
        "-",
        data=(
            b"Authentication-Results: lab.example; spf=pass\n"
            b'Authentication-Results: "Lab Relay"; spf=fail\n'
            b"Authentication-Results: ; spf=pass\n"
        ),
    )
    assert result.returncode == 0
    assert result.stdout.decode().splitlines()[1:] == [
        "Authentication-Results: 3 found, 2 shown, 1 excluded.",
        'Server filter: "lab relay"',
        "Reporter summary (counts of reported method=result claims):",
        '  authserv-id="lab relay" lines=2: spf=fail x1; fields with diagnostics=0',
        "  unattributed lines=3: no tracked claims; fields with diagnostics=1",
    ]


def test_input_and_usage_errors_write_to_stderr_only(tmp_path):
    malformed = cli("--format", "json", "-", data=b"not a header\n")
    missing = cli(tmp_path / "missing.eml")
    bad_option = cli("--server", "\t", "-")
    assert (malformed.returncode, missing.returncode, bad_option.returncode) == (
        1,
        1,
        2,
    )
    assert malformed.stdout == missing.stdout == bad_option.stdout == b""
    assert b"invalid header field" in malformed.stderr
    assert b"missing.eml" in missing.stderr
    assert b"printable ASCII authserv-id" in bad_option.stderr


def test_documented_message_reports_three_claims_and_excludes_relay():
    result = cli("--server", "MX.Recipient.Example", EXAMPLES / "review.eml")
    assert result.returncode == 0
    assert result.stdout.decode().splitlines()[1:] == [
        "Authentication-Results: 2 found, 1 shown, 1 excluded.",
        'Server filter: "mx.recipient.example"',
        'Line 4: authserv-id="mx.recipient.example" version=1 [parsed]',
        '  spf=pass smtp.mailfrom="robot@sender.example"',
        '  dkim=pass header.d="sender.example" header.s="sample"',
        '  dmarc=pass header.from="sender.example"',
    ]


def test_documented_diagnostics_keep_only_intact_claims():
    result = cli(
        "--format", "json", "--server", "lab relay", EXAMPLES / "diagnostics.headers"
    )
    assert result.returncode == 0
    fields = json.loads(result.stdout)["fields"]
    assert [(f["line"], f["status"], f["diagnostics"][0]["code"]) for f in fields] == [
        (2, "partial", "invalid-clause"),
        (6, "invalid", "invalid-structure"),
        (7, "unsupported-version", "unsupported-version"),
        (8, "invalid", "invalid-authserv"),
    ]
    assert [[c["method"] for c in f["claims"]] for f in fields] == [
        ["spf", "dmarc"],
        [],
        [],
        [],
    ]


def test_provenance_fixture_summarizes_conflicting_reporters():
    result = cli("--format", "summary", EXAMPLES / "conflicting-reporters.headers")
    assert result.returncode == 0
    assert result.stderr == b""
    assert result.stdout.decode().splitlines()[1:] == [
        "Authentication-Results: 3 found, 3 shown, 0 excluded.",
        "Reporter summary (counts of reported method=result claims):",
        '  authserv-id="mx.recipient.example" lines=3,10: dkim=fail x1, dmarc=fail x1, '
        "dmarc=pass x1, spf=fail x1; fields with diagnostics=0",
        '  authserv-id="relay.recipient.example" lines=7: dmarc=pass x1, spf=pass x1; '
        "fields with diagnostics=0",
    ]


def test_provenance_fixture_filter_retains_both_claims_from_same_reported_id():
    result = cli(
        "--format",
        "json",
        "--server",
        "mx.recipient.example",
        EXAMPLES / "conflicting-reporters.headers",
    )
    assert result.returncode == 0
    assert result.stderr == b""
    report = json.loads(result.stdout)
    assert (report["total_fields"], report["excluded_fields"]) == (3, 1)
    fields = report["fields"]
    assert [(field["line"], field["authserv_id"]) for field in fields] == [
        (3, "MX.Recipient.Example"),
        (10, "mx.recipient.example"),
    ]
    dmarc = [
        (claim["result"], claim["properties"])
        for field in fields
        for claim in field["claims"]
        if claim["method"] == "dmarc"
    ]
    assert dmarc == [
        ("fail", [{"name": "header.from", "value": "sender.example"}]),
        ("pass", [{"name": "header.from", "value": "sender.example"}]),
    ]
