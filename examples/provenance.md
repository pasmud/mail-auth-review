# Offline mail provenance worksheet

Use [the synthetic saved headers](conflicting-reporters.headers) from the
repository root. The exercise has no live mail or DNS steps.

## 1. Inventory the reported claims

```sh
python -m mail_auth_review --format summary examples/conflicting-reporters.headers
```

| Claimed reporter | Field starting lines | Reported claims |
| --- | --- | --- |
| `mx.recipient.example` | 3, 10 | DKIM fail; DMARC fail and pass; SPF fail |
| `relay.recipient.example` | 7 | DMARC pass; SPF pass |

Each listed outcome occurs once. There are three fields and no parser
diagnostics. Compare the individual claims without merging the reporters'
results: different receiving hops can evaluate different inputs, and the saved
fields do not prove which hop wrote them.

## 2. Check what selection actually does

```sh
python -m mail_auth_review --format json --server mx.recipient.example examples/conflicting-reporters.headers
```

The filter excludes line 7 but keeps lines 3 and 10, including both DMARC
outcomes for the recorded `header.from=sender.example`. The matching IDs,
their capitalization, and their order do not establish which field, if either,
the receiver added.

## 3. Record evidence before attributing a field

| Worksheet prompt | Answer for this exercise |
| --- | --- |
| What was observed? | The saved copy contains the reported claims above. Preserve the original and cite the field starting lines. |
| What would identify a receiver-added field? | A trusted receiving-side record tied to this same delivery, with the actual field that the receiver inserted or a capture that distinguishes it from fields present on ingress. Check the receiver's policy for stripping or retaining incoming `Authentication-Results`. |
| What can I attribute from this file alone? | Nothing to a verified writer. Mark provenance unresolved for all three fields; do not choose the more favorable result or assume the first field is trustworthy. |

For comparison, suppose a **separate, trusted** ingress and post-processing
capture tied to this same delivery showed lines 7–11 were already present on
ingress and that the receiver inserted the field on lines 3–6. If the archive's
header-handling policy corroborated that sequence, you could attribute line 3
to the receiver as its recorded assessment. That evidence is intentionally
absent from the fixture. Attribution would still not independently verify the
SPF, DKIM, or DMARC claims.
