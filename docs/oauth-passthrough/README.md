# OAuth Token Passthrough — project home

Per-user OAuth2 bearer-token passthrough for Trino's Iceberg REST catalog connector
(Trino → Snowflake Horizon / Polaris). This folder is the project's documentation home.

## Where everything lives (read this first)

Both the **issue tracker** and the **code** live in this fork — there is no separate planning repo
anymore:

| What | Where |
| --- | --- |
| Issues / PRD / task tracking | **[`ldocs17/trino` Issues](https://github.com/ldocs17/trino/issues)** |
| Code (implementation branches + PRs) | **`ldocs17/trino`** (this repo) |
| Upstream (rebase source, not a push target) | `trinodb/trino` (git remote `origin`) |
| Push target for the fork | git remote `fork` → `ldocs17/trino` |
| Design narrative (historical) | [`design.md`](./design.md) in this folder |

The epic/PRD is **[issue #3](https://github.com/ldocs17/trino/issues/3)** (`Final Check` label);
the per-issue tasks are labeled `ready-for-agent`.

## Workflow for an implementation agent

1. Pick an open issue labeled `ready-for-agent` from `ldocs17/trino`.
2. Branch off `fork/master` (e.g. `oauth-passthrough/<short-name>`).
3. Implement; run `mvnw airstyle:format` and build/test the affected modules.
4. Push to remote `fork` and open the PR against `ldocs17/trino:master` (the fork is the home; the
   PR is not aimed at upstream `trinodb/trino` unless explicitly decided).
5. Reference the issue it closes in the PR body.

## Issue-number mapping (old planning repo → this fork)

The issues were migrated from the now-closed private repo `ldocs17/trino-oauth-passthrough`.
GitHub could not preserve numbers, so old references resolve as:

| Old (`trino-oauth-passthrough`) | New (`ldocs17/trino`) | Title |
| --- | --- | --- |
| #1 | **#3** | Per-user OAuth token passthrough (epic / PRD) |
| #3 | **#4** | Opt-in per-user OAuth bearer injection (walking skeleton) |
| #4 | **#5** | Decision: FALLBACK identity for tokenless passthrough queries |
| #5 | **#6** | Missing-token behavior — REJECT (default) and FALLBACK |
| #6 | **#7** | Make the config the sole gateway — sanitize, normalize, no-crash |
| #7 | **#8** | Best-effort JWT expiry pre-check |
| #8 | **#9** | Reject passthrough + case-insensitive name matching at startup |
| #9 | **#10** | Cross-user auth-session cache-key guard (security regression) |
| #10 | **#11** | Operational documentation for the Iceberg connector |
| #11 | **#12** | Gated live end-to-end against Snowflake Horizon (HITL) |

Within issue bodies, `#N` cross-references have already been rewritten to the new numbers. Inline
numbers in [`design.md`](./design.md) may still use the old numbering — use this table to resolve.

## Status

The walking skeleton (old #3 / new #4) is implemented and on branch
`oauth-passthrough/walking-skeleton` (PR #1): opt-in per-user bearer passthrough gated by
`iceberg.rest-catalog.oauth2.passthrough-enabled` (default off), token supplied via the
`iceberg.oauth2.token` extra credential and forwarded as-is (no token exchange).
