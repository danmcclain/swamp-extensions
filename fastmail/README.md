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
| `apiToken`   | no\*     | Read-only Fastmail JMAP token (Bearer). Preferred for all read methods. Optional if `writeToken` is set. |
| `writeToken` | no\*     | Write-scoped token. Required by `email_move`; also used as the read token when `apiToken` is unset.  |
| `sessionUrl` | no       | JMAP session discovery URL. Defaults to Fastmail.                                                    |

\* At least one of `apiToken` / `writeToken` is required. Read methods use
`apiToken` when set and otherwise fall back to `writeToken` (a write token also
has read scope); `email_move` always requires `writeToken`.

Tokens are marked sensitive — supply them from a vault, e.g.
`${{ vault.get(local-secrets, FASTMAIL_TOKEN) }}`.

## Methods

| Method           | What it does                                                                                          |
| ---------------- | ---------------------------------------------------------------------------------------------------- |
| `email_senders`  | Fan-out scan of **all** senders across one or more scopes, recording bulk-ness (List-Id / List-Unsubscribe) as a per-sender attribute rather than a filter. |
| `sieve_generate` | Config-driven fan-out that categorizes senders into (nested) folders and writes ready-to-paste Sieve scripts. |
| `email_plan`     | Builds a message-id → destination plan (dry run) from the generated rules.                            |
| `email_analyze`  | Read-only: analyzes a mailbox against the **current** rules and reports what would still be left in the inbox — the rule-candidate list that drives tuning. Moves nothing. |
| `email_move`     | Applies the plan, moving messages into their target folders. Requires `writeToken` and `execute: true`. |

Bulk detection uses the RFC 2369 / 8058 `List-*` headers, fetched via JMAP's
`header:{name}` property syntax (RFC 8621 §4.1.1), so newsletters become one
fallback category rather than swallowing the whole mailbox.

## Tokens & trust

The two tokens map to two privilege levels. **Read** methods (`email_senders`,
`sieve_generate`, `email_plan`, `email_analyze`, and the `valid-api-token` check)
resolve their token as **`apiToken` first, then `writeToken`**; `email_move`
always uses `writeToken` and never falls back to `apiToken`. That gives three
setups:

- **Read-only** — set `apiToken` only. Every read method works; `email_move`
  refuses to run (no write token). The model cannot move a message.
- **Single token** — set `writeToken` only. It drives everything, reads
  included (a write token also has read scope) — the least-config setup.
- **Separate permissions** — set both. Reads run on the least-privilege
  `apiToken`, and only `email_move` uses `writeToken`.

Because reads never require the write token, you don't have to trust the move
workflows to get value: with a read-only `apiToken` you get all the scanning,
Sieve generation, planning, and analysis, and mail can't move until you add a
write-scoped token. A missing write token fails loudly up front in `email_move`
rather than as an opaque JMAP 403 mid-batch.

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
# model instance globalArguments — a read-only token alone unlocks everything
# below except email_move.
apiToken: ${{ vault.get(local-secrets, FASTMAIL_TOKEN) }}
# Optional: add a write-scoped token ONLY when you want email_move to relocate mail.
writeToken: ${{ vault.get(local-secrets, FASTMAIL_WRITE_TOKEN) }}
```

```bash
# All read-only — need only apiToken:
swamp model method run my-fastmail email_senders    # scan senders
swamp model method run my-fastmail sieve_generate   # build Sieve + coverage report
swamp model method run my-fastmail email_analyze    # what's still left in the inbox
swamp model method run my-fastmail email_plan       # preview moves + plan report

# Write path — needs writeToken:
swamp model method run my-fastmail email_move       # apply (needs writeToken)
```
