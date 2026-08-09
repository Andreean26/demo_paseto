---
goal: Presenter-only JWT/PASETO mode control with automatic audience synchronization
version: 1.0
date_created: 2026-08-09
last_updated: 2026-08-09
owner: demo_paseto
status: 'Completed'
tags: [feature, security, realtime, audience, presenter]
---

# Introduction

![Status: Completed](https://img.shields.io/badge/status-Completed-brightgreen)

Port the completed presenter-control and audience-synchronization update from the supplied `live-demo-paseto` repository into this repository while removing every legacy competition-branded label and internal default in favor of Live Demo naming.

## 1. Requirements & Constraints

- **REQ-001**: Only a client holding the runtime presenter key may call `POST /api/mode` or `POST /api/reset`.
- **REQ-002**: The audience page must not display controls that change the server mode.
- **REQ-003**: Connected audience pages must apply presenter mode changes without a page refresh.
- **REQ-004**: An audience with an existing participant name must automatically receive a fresh USER token after the presenter changes mode.
- **REQ-005**: Audience attack controls must match the active mode: JWT forge in JWT mode and one-character tamper in PASETO mode.
- **REQ-006**: No case-insensitive occurrence of the legacy competition name may remain in user-facing copy, documentation, code, configuration defaults, tests, or plans.
- **SEC-001**: Compare presenter keys without exposing the configured or generated key in API responses or public static assets.
- **CON-001**: Use only Node.js built-in modules because the repository intentionally has no runtime dependencies.
- **CON-002**: Preserve the intentionally vulnerable `alg:none` JWT demo behavior.
- **CON-003**: Preserve unrelated target-repository work; the target worktree was clean before implementation.
- **GUD-001**: Reuse the existing `/events` SSE stream as the realtime transport and keep `mode` as server-owned state.
- **PAT-001**: Follow the existing plain HTML, CSS, browser JavaScript, CommonJS, and `node:test` conventions from the supplied source repository.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Enforce presenter ownership of mutable presentation controls.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Update `server.js` to load or generate a presenter key, authorize `POST /api/mode` and `POST /api/reset` using `x-presenter-key`, validate mode input, print keyed presenter URLs, and expose testable server handlers. | ✅ | 2026-08-09 |
| TASK-002 | Update `public/presenter.js` to read the key from the presenter URL, retain it for the browser tab, attach it to protected requests, and surface authorization failures without changing server state. | ✅ | 2026-08-09 |
| TASK-003 | Update `public/presenter.html` and `public/styles.css` with presenter-access guidance and disabled-control styling. | ✅ | 2026-08-09 |

### Implementation Phase 2

- GOAL-002: Make audience mode state read-only, realtime, and consistently Live Demo branded.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-004 | Remove JWT/PASETO mode-change buttons and presenter navigation from `public/audience.html`, rewrite copy to state that the presenter controls the mode, and replace the legacy competition label with Live Demo. | ✅ | 2026-08-09 |
| TASK-005 | Update `public/audience.js` to remove `/api/mode` writes, subscribe to SSE snapshots and mode events, refresh the active participant token after a mode change, ignore stale token responses, and show only the attack action relevant to the selected mode. | ✅ | 2026-08-09 |
| TASK-006 | Replace the presenter heading and server-side legacy default secrets with Live Demo naming. | ✅ | 2026-08-09 |
| TASK-007 | Update `README.md` so setup, presenter URLs, presenter key configuration, audience flow, API authorization, and realtime behavior match the new implementation. | ✅ | 2026-08-09 |

### Implementation Phase 3

- GOAL-003: Add and execute focused regression evidence.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-008 | Add a built-in `node:test` regression suite covering unauthorized rejection, valid presenter mode changes, and observable SSE mode broadcasts; add `npm test` and the generated dependency-free lockfile. | ✅ | 2026-08-09 |
| TASK-009 | Run plan-identifier validation, syntax checks, the regression suite, a repository-wide legacy-brand scan, and a final source-versus-target diff review. | ✅ | 2026-08-09 |

## 3. Alternatives

- **ALT-001**: Copy the source tree wholesale; rejected because explicit patching and diff review provide a safer audit trail and ensure legacy defaults are renamed during the port.
- **ALT-002**: Trust the presenter page only by removing audience buttons; rejected because any audience client could still call the unprotected mode endpoint.
- **ALT-003**: Add a user database and login session; rejected because it adds dependencies and operational scope that are disproportionate for a dependency-free LAN presentation demo.
- **ALT-004**: Poll `/api/state` from audience pages; rejected because the existing SSE transport already provides immediate mode broadcasts with less repeated traffic.

## 4. Dependencies

- **DEP-001**: The supplied source directory `/Users/adamfawazzaky/Documents/Codex/2026-07-02/jal/live-demo-paseto` defines the update set to port.
- **DEP-002**: Node.js 20 or newer with built-in `node:test`, Fetch API, HTTP, crypto, and SSE-compatible streaming.
- **DEP-003**: Browser support for `EventSource`, `sessionStorage`, Fetch API, and the Clipboard API.

## 5. Files

- **FILE-001**: `server.js` owns presenter authorization, shared mode state, SSE broadcasts, Live Demo defaults, and testable server startup.
- **FILE-002**: `public/audience.html` contains audience-only controls, explanatory copy, and Live Demo branding.
- **FILE-003**: `public/audience.js` owns audience state synchronization and token actions.
- **FILE-004**: `public/presenter.html` contains Live Demo branding and presenter-control guidance.
- **FILE-005**: `public/presenter.js` owns presenter-key handling and protected control requests.
- **FILE-006**: `public/styles.css` provides protected-control and mode-action presentation states.
- **FILE-007**: `test/server.test.js` provides backend authorization and SSE regression coverage.
- **FILE-008**: `package.json` and `package-lock.json` expose and lock the dependency-free test command.
- **FILE-009**: `README.md` documents the presentation workflow and security boundary.
- **FILE-010**: `plan/feature-presenter-mode-sync-1.md` records the implementation and its verification status.

## 6. Testing

- **TEST-001**: `npm test` must prove an unauthenticated or incorrectly authenticated audience cannot change mode or reset events.
- **TEST-002**: `npm test` must prove the configured presenter key changes state and emits an SSE `mode` event.
- **TEST-003**: `node --check server.js`, `node --check public/audience.js`, and `node --check public/presenter.js` must pass.
- **TEST-004**: A case-insensitive repository scan must find no occurrence of the legacy three-letter competition name outside `.git`.
- **TEST-005**: A recursive diff against the supplied source must contain only the intentional Live Demo branding/default-secret changes and current plan metadata.

## 7. Risks & Assumptions

- **RISK-001**: Anyone who receives the keyed presenter URL can control the demo; mitigate by generating a new random key at each startup unless `PRESENTER_KEY` is explicitly configured.
- **RISK-002**: A rapid sequence of presenter mode changes can overlap audience token requests; mitigate by ignoring stale token responses using a monotonic request identifier.
- **RISK-003**: Renaming default secrets changes tokens across restarts relative to an older build; acceptable because these are local demo-only defaults and tokens are already ephemeral.
- **ASSUMPTION-001**: The presenter runs the server and can read its terminal output, while audience members receive only the audience URL.
- **ASSUMPTION-002**: Changing mode intentionally invalidates the audience's prior forged or tampered token and starts the next demo stage with a fresh USER token.
- **ASSUMPTION-003**: The branding request applies to both visible labels and internal legacy default secret strings.

## 8. Related Specifications / Further Reading

[Repository README](../README.md)
[HTML EventSource API](https://developer.mozilla.org/en-US/docs/Web/API/EventSource)
