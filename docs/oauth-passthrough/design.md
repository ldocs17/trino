# Trino → Snowflake Horizon: Per-User OAuth Token Passthrough

> **Project Outline & Implementation Guide**
> Engineering Team Reference Document

---

> ## 📍 Relocated (2026-06-08): single home is now `ldocs17/trino`
>
> This project was consolidated. **Issues and code now both live in the fork
> [`ldocs17/trino`](https://github.com/ldocs17/trino).** The former private planning repo
> `ldocs17/trino-oauth-passthrough` is closed out (its issues were migrated and redirected).
>
> For the current workflow and the old→new issue-number mapping, see
> [`README.md`](./README.md) in this folder. Inline issue numbers in the historical text below
> may use the **old** planning-repo numbering — use the mapping table in the README to resolve them.

---

> ## ⚠️ Status update (2026-06-07): mechanism revised — canonical spec is the PRD
>
> The implementation mechanism originally described in this document has been **superseded** after reading the Apache Iceberg 1.11.0 source (the pinned `dep.iceberg.version`). The authoritative, up-to-date spec now lives in the project issue tracker:
>
> **→ [Issue #1: Per-user OAuth token passthrough for Iceberg REST catalog](https://github.com/ldocs17/trino/issues/3)** (label: `ready-for-agent`)
>
> Key corrections (applied inline in the sections below):
> - **Do not rebuild or mutate the `RESTSessionCatalog` per user.** It is a lazily-created, `@GuardedBy("this")` shared singleton. Inject the user token into the per-request `SessionContext.credentials` instead — the seam `TrinoRestCatalog.convert()` already uses.
> - **No Apache Iceberg changes are needed.** Verified that `OAuth2Manager.contextualSession` → `maybeCreateChildSession` uses a per-context `OAuth2Properties.TOKEN` bearer *directly, without token exchange*, and is checked **before** the `JWT_TOKEN_TYPE` exchange path. The "Decision Point" below resolves to **no Iceberg work / no `BearerAuthSession`**.
> - **File names drifted:** `IcebergRestCatalogFactory` → `TrinoIcebergRestCatalogFactory`; `TrinoRestSessionCatalog` → `TrinoRestCatalog`; the config home is `OAuth2SecurityConfig` (not `IcebergSecurityConfig`).
>
> ### Deeper review (2026-06-07): four issues the first pass missed
>
> A line-by-line re-verification against `iceberg-core-1.11.0-sources.jar` and current `trinodb/trino` `master` surfaced four points that are now first-class requirements in the PRD. They sharpen — and in one place **correct** — the bullets above:
>
> - **The resolver is not the only gateway.** `convert()` forwards `getExtraCredentials()` *unfiltered*, and Iceberg honors the raw keys `token` / `credential` / the token-exchange types directly. A client can place a bearer under the literal key `token` and bypass `passthrough-enabled`, `REJECT`, blank-normalization, and the `exp` check entirely — this already works in any `sessionType=USER` OAUTH2 catalog. **`convert()` must strip all Iceberg auth keys from inbound extra credentials and inject only what the resolver authorizes.**
> - **"FALLBACK → static identity" is wrong unless the subject JWT is dropped.** The subject JWT that `convert()` injects under `JWT_TOKEN_TYPE` is in Iceberg's `TOKEN_PREFERENCE_ORDER`, so a tokenless request takes the **token-exchange** branch, *not* the static-parent return. The "subject JWT is inert" claim above holds only in the *inject* path; in the *fallback* path, dropping it is a **correctness requirement** (otherwise FALLBACK uses a subject-JWT exchange identity, not the static service account).
> - **Cross-user safety rests entirely on `sessionId` uniqueness.** Iceberg keys the auth-session cache on `context.sessionId()` alone; the token lives only in the cache-miss loader. Safe today only because `sessionId = user-queryId-source` and `queryId` is unique. The obvious "two tokens → two bearers" test cannot detect a regression that drops `queryId`; an explicit guard is required.
> - **Per-user enforcement covers metadata only.** Data-file reads use Trino's own storage identity via `fileSystemFactory.create(...)` unless `vended-credentials-enabled=true` returns per-user-scoped creds. Pair passthrough with per-user vended credentials for end-to-end enforcement; the Security section's "transparent pass-through" framing applies to the control plane only.
>
> Sections below are retained as historical context. **Where they conflict with the PRD, the PRD wins** — and the four points above are now in the PRD.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Problem Statement](#problem-statement)
3. [Proposed Solution](#proposed-solution)
4. [Technical Architecture](#technical-architecture)
5. [Repositories & Files to Alter](#repositories--files-to-alter)
6. [Setup Decisions & Current State](#setup-decisions--current-state)
7. [Implementation Plan](#implementation-plan)
8. [Effort Summary](#effort-summary)
9. [What Stays the Same](#what-stays-the-same)
10. [Security Considerations](#security-considerations)
11. [Open Questions](#open-questions)
12. [References](#references)

---

## Executive Summary

Currently, Trino's Iceberg connector authenticates to the Snowflake Horizon REST catalog using a single static OAuth2 token configured at the catalog level. This means all users share one service account identity, preventing row-level security, per-user audit trails, and fine-grained Snowflake role enforcement.

This project implements per-user OAuth token passthrough: when a user submits a query to Trino, their own OAuth token is forwarded to Snowflake Horizon, so Snowflake enforces that user's specific permissions on every read/write operation.

> **Key Win:** One shared catalog definition in Trino replaces the need for multiple per-role catalogs. Snowflake's native RBAC enforces access boundaries automatically.

---

## Problem Statement

### Current Architecture

Today's integration works as follows:

- A static token is baked into the Trino catalog properties file (`iceberg.rest-catalog.oauth2.token`)
- Every user querying that catalog impersonates the same Snowflake service account
- Snowflake cannot distinguish between individual Trino users
- To enforce different permissions, teams must maintain separate catalog definitions per role or user group

### Limitations This Creates

| Limitation | Impact |
|---|---|
| **No user attribution** | All Snowflake query history shows the same service account, making auditing impossible |
| **Broken RBAC** | Snowflake role-based access controls are bypassed — everyone gets service account permissions |
| **Static secrets** | Long-lived tokens baked into config files are a security risk |
| **Catalog sprawl** | One catalog per role/team means duplicated config and operational overhead |
| **Token expiry risk** | A single expired token takes down all users simultaneously |

---

## Proposed Solution

Implement extra-credential-based OAuth token passthrough inside Trino's Iceberg REST catalog factory. The user's token is passed via Trino's existing `extraCredentials` mechanism at query time and injected into the REST catalog HTTP client as a per-request `Authorization` header.

### How It Works (High Level)

1. User connects to Trino with their OAuth token passed as an extra credential (e.g. `iceberg.oauth2.token=<bearer>`)
2. Trino's Iceberg connector reads the token from the `ConnectorSession` at query planning time
3. The token is injected into the `RESTSessionCatalog` HTTP client's `AuthSession` for that query
4. All catalog API calls (table listing, metadata fetch, credential vending) go to Snowflake Horizon with the user's token in the `Authorization` header
5. Snowflake enforces the user's own role grants and logs the request under their identity

> **Note:** This builds on Trino's existing extra-credential infrastructure already used for S3 IAM role assumption — the pattern is proven, we are extending it to a new use case.

---

## Technical Architecture

### Component Overview

| Layer | Component | Change Required |
|---|---|---|
| **Client / JDBC** | Trino JDBC driver or DBeaver | Pass token as `extraCredential` on connection |
| **Trino Coordinator** | `ConnectorSession`, `SecurityContext` | Surface extra credential to connector layer *(already available via `session.getIdentity().getExtraCredentials()`)* |
| **Iceberg Connector** | `TrinoRestCatalog.convert()`, `OAuth2SecurityConfig` | Read token from session; **sanitize inbound auth keys**; remap to `OAuth2Properties.TOKEN`; inject into per-request `SessionContext` (controlling the subject JWT per outcome); apply opt-in config |
| **Iceberg Library** | `RESTSessionCatalog`, `OAuth2Manager` | *No changes needed* — `contextualSession` already builds a per-request bearer session from `SessionContext.credentials` |
| **Snowflake Horizon** | Polaris REST API | Validates bearer token against user identity *(no changes needed)* |

### Dependency Relationship

```
trinodb/trino  (your changes — Trino-only)
    └── depends on → apache/iceberg 1.11.0  (read-only; no changes needed)
            └── calls → Snowflake Horizon REST API  (no changes)
```

> **Verified:** the only repo you change is `trinodb/trino`. Iceberg 1.11.0 already supports per-request bearer injection (see the resolved [Decision Point](#decision-point-do-you-need-to-change-the-iceberg-repo)).

---

## Repositories & Files to Alter

### Repo 1 — `https://github.com/trinodb/trino.git`

This is your **primary working repo** — all your actual changes live here.

> ✅ **Status (2026-06-07): cloned now** into `./trino/` (git-ignored). See [Setup Decisions & Current State](#setup-decisions--current-state) for the Windows path-length workaround applied during checkout.

Clone:
```bash
git clone https://github.com/trinodb/trino.git
```

Build (full, skip tests):
```bash
./mvnw clean install -DskipTests
```

Build (scoped to Iceberg plugin only — faster for iterative work):
```bash
./mvnw clean install -DskipTests -pl plugin/trino-iceberg -am
```

> **Java 23** is required. Check your JDK version before building.

---

> ⚠️ **The instructions in Files 1–3 below are the original (superseded) plan.** The corrected mechanism is in [Issue #1](https://github.com/ldocs17/trino/issues/3). Corrected notes are inlined under each file.

#### File 1: `TrinoIcebergRestCatalogFactory.java` *(was `IcebergRestCatalogFactory.java`)*

```
plugin/trino-iceberg/src/main/java/io/trino/plugin/iceberg/catalog/rest/TrinoIcebergRestCatalogFactory.java
```

Currently it reads `iceberg.rest-catalog.oauth2.token` from static config and builds **one shared, lazily-initialized `RESTSessionCatalog` singleton** (`@GuardedBy("this")`).

> ❌ **Original (wrong):** "build the `RESTSessionCatalog` with that user-supplied token."
> ✅ **Corrected:** **Leave the singleton alone** — rebuilding it per user is a concurrency hazard and breaks the shared catalog-config/bootstrap session. The factory keeps building one shared `RESTSessionCatalog`. Per-user injection happens downstream in `TrinoRestCatalog.convert()` (File 2). The factory's only real change is **wiring-time validation**: reject `passthrough-enabled` together with `caseInsensitiveNameMatching` (the factory's singleton-scoped `remoteNamespaceMappingCache` / `remoteTableMappingCache` are populated per-user and would otherwise bleed across identities).

---

#### File 2: `TrinoRestCatalog.java` *(was `TrinoRestSessionCatalog.java`)* — **the actual injection point**

```
plugin/trino-iceberg/src/main/java/io/trino/plugin/iceberg/catalog/rest/TrinoRestCatalog.java
```

> ✅ **Corrected:** `convert(ConnectorSession)` already builds the per-request `SessionContext` and, in `USER` mode, already forwards `session.getIdentity().getExtraCredentials()`. This is the seam.

**What to alter (in `convert()`):**
- Read the user token from extra credentials under the client-facing key `iceberg.oauth2.token`; normalize blank/empty/whitespace → absent.
- **Sanitize inbound auth keys first.** `convert()` currently copies `getExtraCredentials()` verbatim. Strip every key Iceberg treats as auth material — `token`, `credential`, and the `TOKEN_PREFERENCE_ORDER` types (`ID_TOKEN_TYPE`, `ACCESS_TOKEN_TYPE`, `JWT_TOKEN_TYPE`, `SAML2_TOKEN_TYPE`, `SAML1_TOKEN_TYPE`) — so a client cannot smuggle a bearer past the resolver by using Iceberg's native key names. The passthrough config is then the *only* gateway.
- **Remap** the resolved token onto `OAuth2Properties.TOKEN` (literal `"token"`) — the key Iceberg's `OAuth2Manager` consumes. Iceberg uses it as the bearer **with no token exchange** (checked before the exchange branches).
- **Control the subject JWT in every outcome (correctness, not cosmetics):**
  - *inject:* add `OAuth2Properties.TOKEN`; **omit** the subject JWT (`TOKEN` wins precedence, so it is inert here).
  - *fallback:* **omit** the subject JWT *and* inject no token, so `maybeCreateChildSession` falls through to `return parent` and the request genuinely uses the **static service-account** session. Leaving the JWT in makes FALLBACK perform a subject-JWT *token exchange* — a different Snowflake identity. (This corrects the earlier "dropping the JWT is cosmetic" note for the fallback path.)
  - *reject:* throw a clear `TrinoException` *before* the catalog call.
- **Build the credentials map with overwrite semantics, not `ImmutableMap.Builder.buildOrThrow()`** — the current builder throws an opaque `IllegalArgumentException` (500) if an inbound key collides with an injected one. Sanitizing first removes the collision; overwrite semantics make it robust.
- **Keep the `USER`-mode `sessionId` (`user-queryId-source`) and guard it.** Iceberg keys the contextual-session cache by `sessionId` **alone** — the token is read only in the cache-miss loader — so this is the *sole* thing preventing cross-user bleed. Add a comment marking it security-load-bearing and a guard/assertion that the id includes the unique `queryId`. **Distinct tokens must never share a `sessionId`;** do not "optimize" it to `user-source`.

Extract the *decision* logic into a pure, dependency-free `PassthroughTokenResolver` (unit-testable without Iceberg or a network); keep the sanitize-then-inject *mechanics* in `convert()`. See PRD for the resolver's three-outcome contract and the required regression tests (sanitization, fallback-identity, and the cross-user cache-key guard).

---

#### File 3: `OAuth2SecurityConfig.java` *(was `IcebergSecurityConfig.java`)*

```
plugin/trino-iceberg/src/main/java/io/trino/plugin/iceberg/catalog/rest/OAuth2SecurityConfig.java
```

**What to alter:**
- Add `iceberg.rest-catalog.oauth2.passthrough-enabled` (boolean, default off) — explicit operator opt-in.
- Add `iceberg.rest-catalog.oauth2.missing-token-behavior` (enum, default **`REJECT`**; `FALLBACK` for transitional rollouts). Note `FALLBACK` is Iceberg's built-in default behavior; `REJECT` is the one that needs active enforcement.
- **Keep** the existing `credentialOrTokenPresent()` assertion — the static token is the required **bootstrap** credential for the one-time `GET /v1/config` route (which runs with no user session in scope).
- Recommend `token-refresh-enabled=false` for passthrough catalogs (Trino can't refresh a user's bearer).
- Each `@Config` setter needs a `@ConfigDescription`; secrets stay `@ConfigSecuritySensitive`; add `ConfigAssertions` tests.

---

#### File 4: Integration Tests

```
plugin/trino-iceberg/src/test/java/io/trino/plugin/iceberg/catalog/rest/
```

**What to add:**
- New or extended integration tests validating that a token passed as an extra credential reaches Snowflake Horizon correctly
- Tests should verify different users receive different Snowflake permissions based on their token

---

### Repo 2 — `https://github.com/apache/iceberg.git`

You **won't commit changes here**, and you don't even need to clone it.

> ✅ **Status (2026-06-07): resolved — no Iceberg work needed.** Verified directly against the `iceberg-core-1.11.0-sources.jar`. Cloning the repo is unnecessary; if you want to read along, pull the sources jar from Maven Central instead of cloning the full tree.

Clone:
```bash
git clone https://github.com/apache/iceberg.git
```

---

#### File 1: `RESTSessionCatalog.java` *(read deeply)*

```
core/src/main/java/org/apache/iceberg/rest/RESTSessionCatalog.java
```

**What to understand:**
- This is the underlying HTTP client that actually calls the Snowflake Horizon REST API
- It has an internal `AuthSession` it uses to set the `Authorization` header on every request
- Find where it builds the initial auth session from config — **that is the seam you will exploit** from the Trino side
- You are not changing this file directly; you are learning how to inject into it

---

#### File 2: `auth/` directory *(read, possibly implement)*

```
core/src/main/java/org/apache/iceberg/rest/auth/
```

**What to understand / potentially alter:**
- The `AuthSession` interface and its implementations live here
- Look for an existing implementation that accepts a pre-supplied bearer token (e.g. `BearerAuthSession`)
- **If one exists:** use it directly from the Trino factory — no Iceberg changes needed
- **If one does not exist:** two options:
  1. Implement it in this repo and submit an upstream PR to Apache Iceberg
  2. Implement a thin `BearerAuthSession` inner class inside the Trino plugin as a faster path

---

### Decision Point: Do You Need to Change the Iceberg Repo? — **RESOLVED: No**

Verified against Iceberg 1.11.0 source:

- `RESTSessionCatalog` calls `authManager.contextualSession(context, catalogAuth)` for **every** catalog operation (30+ call sites) and attaches the result to the HTTP client.
- `OAuth2Manager.contextualSession` → `maybeCreateChildSession` checks `OAuth2Properties.TOKEN` **first** and uses that bearer directly (source comment: *"use the bearer token without exchanging"*), **before** the `JWT_TOKEN_TYPE` token-exchange branch.
- When no per-context token is present, it returns the parent (static `catalogAuth`) — so **static-token fallback is built in, for free**.
- `OAuth2Properties.TOKEN == "token"`; the static bootstrap session that authenticates `GET /v1/config` is built by `OAuth2Manager.initSession`.

So there is **no `BearerAuthSession` to write and no Iceberg patch to publish**. The whole feature is Trino-side credential remapping + config. If you want to read the source without cloning:

```bash
# Fastest: pull just the sources jar (no full clone, no build)
curl -fsSL -o iceberg-core-1.11.0-sources.jar \
  https://repo1.maven.org/maven2/org/apache/iceberg/iceberg-core/1.11.0/iceberg-core-1.11.0-sources.jar
```

---

## Setup Decisions & Current State

> **Snapshot as of 2026-06-07.** This section records concrete decisions made while setting up the working environment, keeping the aspirational plan above distinct from what has actually been done.

### Project repository

- Progress is tracked in a dedicated **private** GitHub repo: `https://github.com/ldocs17/trino-oauth-passthrough`
- This planning doc lives at the repo root (`trino_oauth_passthrough.md`)

### Repos cloned: now vs. later

| Repo | Decision | Location |
|---|---|---|
| `trinodb/trino` | **Cloned now** — primary working repo | `./trino/` (git-ignored) |
| `ldocs17/trino` *(fork)* | **Fork created 2026-06-07** — implementation changes go here; PRs opened against upstream from this fork | remote `fork` in `./trino/` |
| `apache/iceberg` | **Deferred** — no Iceberg changes needed; sources jar sufficient if reading along | *not yet cloned* |

Both `trino/` and `iceberg/` are listed in `.gitignore`, so these large upstream clones are never committed into the project repo — they are local working/build areas only.

### Windows path-length workaround

Cloning `trinodb/trino` on Windows hits the 260-character path limit on deeply-nested `trino-delta-lake` test fixtures.

> **Updated 2026-06-07 (second pass):** The original workaround used a one-off `core.longpaths` flag (deliberately not persisted) and a `--no-cone` sparse-checkout that tried to exclude `plugin/trino-delta-lake/src/test/resources`. That sparse-checkout file was later found to be **corrupted**: MSYS/Git-Bash converted the leading-slash exclusion patterns (e.g. `!/plugin/...`) into Windows absolute paths (`!C:/Program Files/Git/plugin/...`), so the exclusions silently stopped working — delta-lake resources stayed in the checkout and couldn't materialize, producing 68 phantom `D` entries and 1 spurious `M`. Fixed:
>
> - `core.longpaths=true` is now **persisted** to the clone's git config (`git config core.longpaths true`).
> - Sparse-checkout replaced with **cone mode** scoped to `plugin/trino-iceberg` (`git sparse-checkout set --cone plugin/trino-iceberg`). Cone paths contain no leading slash, so MSYS cannot mangle them. Working tree is clean on `master`.
> - All work for this project is in `plugin/trino-iceberg`; the delta-lake fixtures are never needed.

If a full reactor build is needed later (e.g. running all tests with `-pl plugin/trino-iceberg -am`), widen the cone incrementally:
```bash
git sparse-checkout add plugin/trino-iceberg core/trino-spi core/trino-main  # expand as needed
```
Or disable sparse entirely with `git sparse-checkout disable` to materialize the full tree.

### File-naming reconciliation (upstream drift)

The file names in the plan above predate the current `trinodb/trino` `master`. Current upstream equivalents (reconciled 2026-06-07):

| Plan reference | Current upstream file |
|---|---|
| `IcebergRestCatalogFactory.java` | `TrinoIcebergRestCatalogFactory.java` |
| `TrinoRestSessionCatalog.java` | `TrinoRestCatalog.java` |
| `IcebergSecurityConfig.java` | `OAuth2SecurityConfig.java` |

All three live in `plugin/trino-iceberg/src/main/java/io/trino/plugin/iceberg/catalog/rest/`. The injection seam is `TrinoRestCatalog.convert()` (confirmed), not the factory.

### Implementation fork & branch

All Trino source changes are developed on a branch of the `ldocs17/trino` fork so they can become an upstream PR without touching `master` directly.

| Item | Value |
|---|---|
| Fork | `https://github.com/ldocs17/trino` |
| Upstream remote | `origin` → `trinodb/trino` (for rebasing on upstream) |
| Fork remote | `fork` → `ldocs17/trino` (push target) |
| Implementation branch | `oauth-passthrough/walking-skeleton` (issue #3 — per-user OAuth bearer injection) |

Workflow:
```bash
# Start working (you are already here after setup)
cd trino/
git switch oauth-passthrough/walking-skeleton

# First push to fork
git push -u fork oauth-passthrough/walking-skeleton

# Stay current with upstream
git fetch origin master
git rebase origin/master
```

When ready to open the upstream PR, reference the planning issues as `ldocs17/trino-oauth-passthrough#3` etc. in the PR description.

---

### Automation (remote routines)

Two manually-triggerable remote agents (with a weekly safety-net schedule) operate on the project repo:

- **Auto-fix oldest unassigned issue** — opens a `fix/issue-<n>` PR labeled `awaiting-review`; never pushes to `main`
- **Review awaiting-review PRs** — posts a structured review comment (Summary / Concerns / Verdict: LGTM or NEEDS CHANGES); never approves or merges

---

## Implementation Plan

| Phase | Description | Key Files / Components | Est. Effort |
|---|---|---|---|
| **Phase 1** | Codebase familiarization — read `IcebergRestCatalogFactory`, `RESTSessionCatalog`, and `AuthSession` to understand the token lifecycle | `IcebergRestCatalogFactory.java`, `RESTSessionCatalog.java` | 1–2 days |
| **Phase 2** | Extra credential extraction — implement reading `iceberg.oauth2.token` from `ConnectorSession.getExtraCredentials()` | `ConnectorSession`, `IcebergSecurityConfig` | 1 day |
| **Phase 3** | Per-request `AuthSession` injection — build a custom `AuthSession` backed by the user token; configure `RESTSessionCatalog` to use it | `IcebergRestCatalogFactory`, `RESTSessionCatalog` | 2–3 days |
| **Phase 4** | Fallback handling — graceful degradation to static token if no extra credential present; configuration flag for opt-in | `IcebergSecurityConfig`, `IcebergRestCatalogFactory` | 1 day |
| **Phase 5** | Integration testing — validate against Snowflake Horizon with real user tokens; verify different users get different Snowflake permissions | Test environment, Snowflake sandbox account | 2–3 days |
| **Phase 6** | Token expiry & edge cases — handle expired tokens gracefully, return clear error messages; test long-running query behavior | Error handling layer, integration tests | 1–2 days |

---

## Effort Summary

| Item | Detail |
|---|---|
| **Total Estimate** | 8–12 developer-days (solo; faster with a pair) |
| **Java Expertise** | Required — Trino is a Java codebase; Iceberg library is also Java |
| **Env Setup** | Working Trino dev environment + Snowflake sandbox account with Horizon enabled |
| **~~Risk: Singleton scope~~ (resolved)** | Confirmed: `RESTSessionCatalog` is a shared singleton; per-request injection is safe via `SessionContext.credentials`. Do **not** rebuild the singleton. |
| **Risk: cross-user bleed (mitigated, needs guard)** | Safe **only because** the auth-session cache key `sessionId = user-queryId-source` is unique per query; the token is *not* in the cache key. Requires a regression guard + a comment pinning the `queryId` component (see File 2 / PRD). |
| **Risk: incomplete gateway (open)** | `convert()` forwards raw extra credentials unfiltered, so `token`/`credential` bypass the opt-in/reject/expiry controls. Must sanitize inbound auth keys; without it the opt-in gate is not authoritative. |
| **Risk: FALLBACK identity (open)** | Must drop the subject JWT in the fallback path or FALLBACK uses a token-exchange identity instead of the static service account. Decide + test. |
| **Risk: data-plane scope (open)** | Per-user enforcement is metadata-only unless paired with `vended-credentials-enabled`. Document or require. |
| **~~Risk: Token refresh~~ (resolved)** | Out of scope — user bearers aren't refreshable by Trino; use `token-refresh-enabled=false` + fail-fast `exp` check + TTL guidance. |
| **Upstream path** | Feature is tracked in Trino issue #27197 — implementation could be contributed back |

---

## What Stays the Same

This change is **additive and backward compatible**:

- The Trino catalog properties file still exists and is still required
- Existing static token config (`iceberg.rest-catalog.oauth2.token`) continues to work as a fallback
- No changes to Snowflake Horizon or the Polaris REST catalog API
- No changes to any other Trino connector or catalog type
- Workers, coordinators, and deployment topology are unaffected

---

## Security Considerations

> ⚠️ **Important:** Extra credentials in Trino are transmitted over the client protocol connection and are not logged by default. Ensure TLS is enforced on all Trino client connections before enabling this feature.

- User tokens never touch disk or appear in catalog properties files
- Each query is authenticated under the querying user's identity in Snowflake's audit log
- Token scope is bounded to the lifetime of the query session
- Snowflake's native RBAC becomes the enforcement boundary for **catalog/metadata** operations

> ⚠️ **Control plane vs. data plane.** Passthrough authenticates the *catalog* calls per user. The underlying object-store reads/writes go through Trino's own storage identity (`fileSystemFactory.create(...)`) **unless `iceberg.rest-catalog.vended-credentials-enabled=true`** returns per-user-scoped credentials from Snowflake. For genuine end-to-end per-user enforcement, pair passthrough with per-user vended credentials — otherwise a user who passes the metadata-layer check can still reach the data via the shared identity.

> ⚠️ **The config is the only gateway only if `convert()` sanitizes inbound keys.** Without stripping, a client can pass a bearer under the raw `token` key and bypass the opt-in / reject / expiry controls (see File 2). This is required, not optional.

> ℹ️ **Cache footprint.** Iceberg's auth-session cache evicts by `expireAfterAccess` (default 1h) with no size bound; per-query `sessionId`s mean one entry per query for the TTL. Tune `iceberg.rest-catalog.session-timeout` down for high-QPS deployments. With `token-refresh-enabled=false`, no refresh threads accumulate.

---

## Open Questions

**Still open:**
- How are users currently obtaining their Snowflake OAuth tokens? Is there an existing SSO/IdP flow we can integrate with, or will users pass tokens manually?
- **(Must verify before finalizing)** Does Snowflake Horizon require authentication on `GET /v1/config`? The static bootstrap token is treated as required because that route runs with no user session; confirm against the sandbox.
- **(Must decide) FALLBACK identity.** `missing-token-behavior=FALLBACK` is specified as "use the static service-account session" (subject JWT dropped). Confirm that is the intended fallback — the alternative (keep the subject JWT → token-exchange identity) is a *different* Snowflake principal. Pin it and test it.
- **(Must decide) Data-plane enforcement.** Do we require/recommend `vended-credentials-enabled=true` alongside passthrough so object-store access is also per-user, or document the limitation and leave it to the operator?
- Should we contribute this upstream to the Trino open source project (tracked as issue [#27197](https://github.com/trinodb/trino/issues/27197))?
- What is the rollout plan? Blue/green alongside existing static-token catalog, or hard cutover? (`missing-token-behavior=FALLBACK` supports a transitional period.)

**Resolved:**
- ~~Do we need per-query token refresh?~~ **No.** Extra credentials are fixed at connection time and a user bearer isn't refreshable by Trino. Mitigation = best-effort JWT `exp` fail-fast + operator guidance that token TTL exceed query duration. Mid-query renewal is out of scope (see PRD).

---

## References

| Source | Description |
|---|---|
| [PRD — Issue #1 (this project)](https://github.com/ldocs17/trino/issues/3) | **Canonical, up-to-date spec.** Supersedes the mechanism in this document. |
| [Trino Issue #27197](https://github.com/trinodb/trino/issues/27197) | Enable Extra-Credential Support for Iceberg OAuth Token — open feature request tracking this exact gap |
| [Trino Discussion #24403](https://github.com/trinodb/trino/discussions/24403) | User identity pass-through to external Iceberg catalog — community design thread |
| [Apache Iceberg #12735](https://github.com/apache/iceberg/issues/12735) | REST Catalog: Allow JWT token via headers instead of full OAuth2 flow — upstream library discussion |
| [Trino Iceberg Connector Docs](https://trino.io/docs/current/connector/iceberg.html) | Official Iceberg connector configuration reference |
| [Iceberg REST Catalog Spec](https://github.com/apache/iceberg/blob/main/open-api/rest-catalog-open-api.yaml) | Official Apache Iceberg REST Catalog API specification |
