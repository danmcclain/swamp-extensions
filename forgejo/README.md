# @dmc/forgejo

Forgejo site-administrator work for
[swamp](https://github.com/swamp-club/swamp), over the Forgejo API.

The type `@dmc/forgejo/admin` makes a limited service account, gives it a
repository, and makes an access token for it. It was written for accounts that
own CI runners. For example, a test runner pool registers its runners with the
token of a separate account, so it never holds the token of the main account.

## Methods

| Method                   | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ensureUser`             | Makes a local account with a generated password, or sets the limits of an existing account: `restricted`, `visibility`, `maxRepoCreation` and `allowCreateOrganization`. Never changes the password, email or admin flag of an existing account.                                                                                                                                                                                                                                                                                           |
| `ensureRepo`             | Makes a repository for a user (as admin, with a README on `main`), sets it private or not, turns the Actions unit on or off, and adds collaborators with a permission. Never deletes a repository and never removes a collaborator.                                                                                                                                                                                                                                                                                                        |
| `ensureUserToken`        | Makes an access token for an account, with exact scopes and no admin scope. It checks the new token with `GET /user`: the token must belong to that account, and the account must not be an admin. If a check fails, or the vault cannot store the token, the method deletes the token. Never changes or deletes an existing token.                                                                                                                                                                                                        |
| `ensureCollaborator`     | Adds a user as a collaborator with a permission to many repositories of one owner (`repos`: a list, or `all` with `exclude`), or changes its permission. The repositories may belong to a site administrator; the collaborator must not be one. Reads every repository first and changes none while any blocker exists. Never removes a collaborator.                                                                                                                                                                                      |
| `ensureUserKey`          | Adds one SSH public key (ed25519 or ECDSA) to an account, for git over SSH and SSH commit signing. Refuses a private key, RSA and multi-line text. A key the account already has is reported unchanged. Data keeps the fingerprint and the `verified` flag, never the key. Never removes a key.                                                                                                                                                                                                                                            |
| `ensureBranchProtection` | Makes or changes the protection rule of one branch on many repositories of one owner (`repos`: a list, or `all` with `exclude`): direct push `denied` (pull requests only), limited to a push allowlist, or `allowed`; a merge allowlist (an empty list lets any writer merge); and, when given, dismiss stale approvals. Keeps status checks and all other settings. Each allowlist user must be the owner or have write access, because Forgejo silently drops other users; each rule is read back and must match. Never deletes a rule. |

All methods:

- are a dry run by default (`dryRun: true`). A dry run reads and plans, and
  writes nothing.
- read first. If there is a blocker, they change nothing in Forgejo, record the
  blocker, and fail (also in a dry run), so a workflow stops there.
- refuse to manage a site administrator, an account with `prohibit_login`
  (Forgejo also refuses API tokens for such an account) and an inactive account.
- need a token whose user is a site administrator (the `token-is-admin` check).

## Secrets

A new account's password (40 random characters) and a new token are **sensitive
outputs**. swamp stores them in the vault and keeps only a vault reference in
data. Nothing prints them. To read one, use a CEL expression:

```yaml
${{ data.latest("forgejo-admin", "runner-pool-testing--runner-registration-token").attributes.token }}
```

Forgejo shows a token only once. When a token with the same name and the same
scopes already exists, `ensureUserToken` reports it `unchanged` and does not
issue a secret. To get a new one, delete the old token in Forgejo first.

The client sends the token only in the `Authorization` header, does not follow
redirects, accepts only `https` base URLs, and removes the token and the new
password from every error message.

## Data

| Resource       | Data name                              | Content                                                                                                                                      |
| -------------- | -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `user`         | `{username}-user`                      | Plan, actions, blockers and check of `ensureUser`                                                                                            |
| `password`     | `{username}-password`                  | The generated password (sensitive), only when `ensureUser` made the account                                                                  |
| `repo`         | `{owner}--{repo}-repo`                 | Plan, actions, blockers and check of `ensureRepo`                                                                                            |
| `tokenAccess`  | `{username}--{tokenName}-token-access` | Plan, token ID, scopes and check of `ensureUserToken`                                                                                        |
| `token`        | `{username}--{tokenName}-token`        | The token (sensitive), only when `ensureUserToken` made it                                                                                   |
| `collaborator` | `{owner}--{collaborator}-collaborator` | One row per repository (permission before, state), skipped repositories and blockers of `ensureCollaborator`                                 |
| `key`          | `{username}--{title}-key`              | Plan, key type, key ID, fingerprint and `verified` of `ensureUserKey`                                                                        |
| `protection`   | `{owner}--{rule}-protection`           | One row per repository (created, changed settings, kept status checks, state), skipped repositories and blockers of `ensureBranchProtection` |

Usernames, repository names and token names must be lowercase letters and digits
in groups joined by single hyphens. So `--` in a data name separates the owner
from the repository or token in one way only.

## Setup

The admin token needs `write:admin`, `write:repository` and `read:user`. Make a
short-lived token, store it in a vault, and delete it after use.

```bash
swamp model create @dmc/forgejo/admin forgejo-admin \
  --global-arg apiUrl=https://forgejo.example.com \
  --global-arg token='${{ vault.get(infra, "Forgejo admin/credential") }}'

# Dry run first: each method writes nothing until dryRun is false.
swamp model method run forgejo-admin ensureUser \
  --input username=runner-pool-testing \
  --input email=runner-pool-testing@example.com
```

A workflow usually runs the three methods in order: `ensureUser`, then
`ensureRepo` (with the main account as a collaborator), then `ensureUserToken`
with `scopes: ["write:user"]` (the scope that lets the account manage its own
user-level Actions runners).

## Fan-out over repositories

`ensureCollaborator` and `ensureBranchProtection` take `repos`: a list of
repository names, or `all` for every repository the owner owns. With `all`,
archived repositories and mirrors are skipped and listed in the record, and a
name the extension cannot use in data names (uppercase, dots, underscores)
blocks the run until it is added to `exclude`, so no repository is left out
silently. Each run reads every repository first, changes none while any blocker
exists, and writes one record. Forgejo has no protection rule above the
repository (no user, organization or server rules), so a fan-out run is how one
policy covers many repositories; run it again after you make a repository.

## Branch protection

Forgejo's API calls the allowlists `push_whitelist_*` and `merge_whitelist_*`;
`ensureBranchProtection` uses the words push allowlist and merge allowlist.
Repository admins (and site administrators) still bypass a rule, because the
method does not set `apply_to_admins`. A typical rule for a repository where a
service account may only open pull requests:

```yaml
directPush: denied # every change comes through a merged pull request
mergeAllowlist: [dmc] # only dmc may merge
dismissStaleApprovals: true
```

## SSH commit signing

Forgejo shows an SSH-signed commit as verified only when all of these hold
(`models/asymkey/ssh_key_object_verification.go`):

- the key belongs to the committer's account and is **verified**;
- the commit's committer email is an activated email of that account.

Only the account's own user can verify a key, in the web UI (Settings, SSH / GPG
keys, Verify: sign the shown token with the key). There is no API for it
(`routers/web/user/setting/keys.go`), so `ensureUserKey` reports `verified` but
cannot set it.

## Facts from the Forgejo source

From Forgejo v16.0.6 (tag `v16.0.6`, commit 1aa1394):

- `POST /admin/users` needs a password for a local account. `prohibit_login`
  also refuses API tokens (`routers/api/shared/middleware.go`), so an account
  that only uses tokens still needs a password.
- A restricted user can still own repositories (`CanCreateRepo` does not check
  `IsRestricted`). Restricted only hides other users' public repositories and
  organizations.
- `api.User` does not show `max_repo_creation` or `allow_create_organization`,
  so `ensureUser` sets the limits on each live run (the call is idempotent).
- `PATCH /admin/users/{username}` needs `source_id` and `login_name` together;
  `ensureUser` sends source 0 (local) and the username.

## Development

```bash
~/.swamp/deno/deno check extensions/models/forgejo_admin.ts
~/.swamp/deno/deno test -A extensions/models/
```

## License

MIT. See [LICENSE.md](LICENSE.md).
