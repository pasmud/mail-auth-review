# mail-auth-review

Review **reported SPF, DKIM, and DMARC claims** in a saved email or header
block. The tool runs locally with no runtime dependencies beyond Python 3.11+.

**Trust boundary:** `Authentication-Results` is evidence of what the saved
file says, not proof of who wrote it or whether its claims are accurate. A
matching reporting ID only selects fields. Establish provenance separately
from the receiving system's trusted records and header-handling policy. This
tool does not check signatures, DNS, domain alignment, or delivery history.

## Quick start

From the repository root, try the bundled synthetic `.eml`:

```sh
python -m mail_auth_review --server MX.Recipient.Example examples/review.eml
```

```text
Reported claims only; this review does not verify authenticity or who wrote a field.
Authentication-Results: 2 found, 1 shown, 1 excluded.
Server filter: "mx.recipient.example"
Line 4: authserv-id="mx.recipient.example" version=1 [parsed]
  spf=pass smtp.mailfrom="robot@sender.example"
  dkim=pass header.d="sender.example" header.s="sample"
  dmarc=pass header.from="sender.example"
```

For structured output from the synthetic header-only fixture:

```sh
python -m mail_auth_review --format json --server 'Lab Relay' - < examples/diagnostics.headers
```

The first field in that report retains its SPF and DMARC claims and flags its
malformed DKIM clause. The unclosed comment in the next field suppresses that
field's claims. The report also shows an unsupported version and an
unattributed diagnostic.

## Input and selection

- Pass one local file path or `-` for stdin. A header-only file can end at EOF,
  even without a final newline. For a full `.eml`, the first empty line ends
  the header block. The message body is not inspected.
- LF and CRLF are accepted. A line starting with space or tab continues the
  preceding field. Only the `Authentication-Results` field name is matched,
  case-insensitively; related headers such as `ARC-Authentication-Results`
  are out of scope.
- Limits: 65,536 bytes through the header separator or EOF, 8,192 bytes per
  physical line (including its newline), and 256 fields. An individual
  `Authentication-Results` field can have up to 128 result clauses.
- Omit `--server` to show all fields. Repeat `--server ID` to select any of
  those IDs. Matching is exact after ASCII case folding: no suffixes,
  wildcards, or trailing-dot normalization. Pass a quoted ID's decoded text
  (e.g. `'Lab Relay'` at the shell). Diagnostics with no parseable reporting
  ID remain visible under every filter.

## Reading the output

Text is the default; `--format json` provides schema version `1`. Output
preserves source order, including duplicate fields, results, and properties.
No overall pass/fail is inferred. A reported result may be an unfamiliar
keyword; it is not normalized to a known authentication outcome.

JSON contains `schema_version`, `notice`, `server_filter` (sorted, lowercase,
and deduplicated), `total_fields`, `excluded_fields`, and `fields`. Each
shown field has `line` (one-based physical starting line), `authserv_id`,
`version`, `status`, `claims`, and `diagnostics`. IDs and versions may be
`null` when the prefix cannot be parsed. Each claim includes `method`,
`result`, `method_version`, `reason` (or `null`), and an ordered array of
`properties` (`name`/`value` pairs). Versions are decimal strings, default to
`"1"` when omitted, and omit leading zeros. Diagnostic objects contain `code`,
`message`, and `clause` (one-based after the authserv-id, or `null` for a
field-level issue). Header property values and reasons may contain personal
data in real messages; handle reports accordingly.

| Status | Meaning |
| --- | --- |
| `parsed` | All clauses parsed; the claim list is empty if none were SPF, DKIM, or DMARC. |
| `partial` | At least one clause parsed; malformed clauses were dropped and diagnosed. |
| `none` | The field contained the standalone `none` marker. |
| `invalid` | No usable clause, a bad prefix, ambiguous quote/comment boundaries, conflicting `none`, or an oversized clause list. This field contributes no claims. |
| `unsupported-version` | The reporting ID was parsed, but the field declares an authres version other than 1, so no claims are interpreted. |

The parser covers a practical ASCII subset of Authentication-Results syntax:
unfolding, nested comments, quoted strings and escapes, method versions, and
reason and property assignments. Quoted values and simple bare property
values (including unquoted mailboxes) are retained as text; their internal
syntax and semantics are not validated. Composite values such as a quoted
local part followed by an unquoted domain are not supported. Semicolons in
comments and quotes do not split clauses. Empty clauses, including a trailing
semicolon, are diagnosed rather than treated as results.

| Exit | Meaning |
| --- | --- |
| `0` | Review completed, including no matches or field-level diagnostics. |
| `1` | File could not be read, header framing was malformed, or a header-block limit was exceeded. Diagnostic on stderr; no report. |
| `2` | Invalid command-line arguments. Usage error on stderr; no report. |

Licensed under the [MIT License](LICENSE).
