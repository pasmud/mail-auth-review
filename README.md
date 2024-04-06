# mail-auth-review

Offline inspection of `Authentication-Results` fields in saved email headers.
These fields contain reported claims. A saved header does not prove the
message is authentic or that the named server wrote the field.

Run with Python 3.11 or newer: `python -m mail_auth_review message.eml`.
Use `-` to read from standard input. Only the header block is inspected.
