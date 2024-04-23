import json
import subprocess
import sys


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
