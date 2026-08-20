# @dmc/fastmail

A Fastmail email-organization pipeline built on **JMAP** (RFC 8620/8621). It
scans your senders, classifies bulk/newsletter mail from the RFC 2369/8058
`List-*` headers, generates ready-to-paste **Sieve** scripts that file senders
into (nested) folders, and plans/applies message moves — with reports that audit
senders, measure rule coverage, and review an apply plan before you run it.

The model is self-contained (a small JMAP transport lives inside it) and depends
only on `zod`. It talks to Fastmail's JMAP session endpoint
(`https://api.fastmail.com/.well-known/jmap`) by default.

## Global arguments

| Arg          | Required | Description                                                                                         |
| ------------ | -------- | --------------------------------------------------------------------------------------------------- |
| `apiToken`   | yes      | Fastmail JMAP API token (Bearer). Read-only scope is enough for every method except `email_move`.   |
| `writeToken` | no       | Write-scoped token used **only** by `email_move` (`execute: true`). Omit to keep the model read-only. |
| `sessionUrl` | no       | JMAP session discovery URL. Defaults to Fastmail.                                                    |

Tokens are marked sensitive — supply them from a vault, e.g.
`${{ vault.get(local-secrets, FASTMAIL_TOKEN) }}`.

## Methods

| Method           | What it does                                                                                          |
| ---------------- | ---------------------------------------------------------------------------------------------------- |
| `email_senders`  | Fan-out scan of **all** senders across one or more scopes, recording bulk-ness (List-Id / List-Unsubscribe) as a per-sender attribute rather than a filter. |
| `sieve_generate` | Config-driven fan-out that categorizes senders into (nested) folders and writes ready-to-paste Sieve scripts. |
| `email_plan`     | Builds a message-id → destination plan (dry run) from the generated rules.                            |
| `email_move`     | Applies the plan, moving messages into their target folders. Requires `writeToken` and `execute: true`. |

Bulk detection uses the RFC 2369 / 8058 `List-*` headers, fetched via JMAP's
`header:{name}` property syntax (RFC 8621 §4.1.1), so newsletters become one
fallback category rather than swallowing the whole mailbox.

## Reports

All three are `scope: method` and render automatically after the run that
produces their data:

- **`@dmc/fastmail-audit`** — reads the `senders` artifacts from a run and
  audits the sender inventory (bulk vs. personal, coverage gaps).
- **`@dmc/fastmail-coverage`** — reads the `sieve` artifacts from a
  `sieve_generate` run and reports rule coverage.
- **`@dmc/fastmail-plan`** — renders the message-id → destination plan grouped
  by folder so you can review it before `email_move`.

## Example

```yaml
# model instance globalArguments
apiToken: ${{ vault.get(local-secrets, FASTMAIL_TOKEN) }}
# writeToken only needed to actually move mail:
writeToken: ${{ vault.get(local-secrets, FASTMAIL_WRITE_TOKEN) }}
```

```bash
swamp model method run my-fastmail email_senders    # scan senders
swamp model method run my-fastmail sieve_generate   # build Sieve + coverage report
swamp model method run my-fastmail email_plan       # preview moves + plan report
swamp model method run my-fastmail email_move       # apply (needs writeToken)
```
