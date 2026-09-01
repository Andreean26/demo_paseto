---
goal: Remove presenter key requirements from the Live Demo PASETO presenter controls
version: 1.0
date_created: 2026-09-01
last_updated: 2026-09-01
owner: demo_paseto
status: 'Completed'
tags: [refactor, presenter, api]
---

# Introduction

![Status: Completed](https://img.shields.io/badge/status-Completed-brightgreen)

Remove the no-longer-required presenter key from the presenter page and protected mode-management API while preserving mode validation and real-time synchronization.

## 1. Requirements & Constraints

- **REQ-001**: `POST /api/mode` and `POST /api/reset` must work without a presenter key or `x-presenter-key` header.
- **REQ-002**: The presenter page must allow mode changes and event resets directly, with no key query parameter, session storage, or access-status UI.
- **REQ-003**: README setup, API documentation, and presentation flow must no longer mention `PRESENTER_KEY` or a keyed presenter URL.
- **CON-001**: Preserve the existing `jwt`/`paseto` mode validation, SSE broadcasts, audience synchronization, and dependency-free Node.js implementation.
- **PAT-001**: Continue using the existing `node:test` server-handler regression style in `test/server.test.js`.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Remove the presenter-key authorization path at its server and browser owners.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | In `server.js`, delete the generated/configured `PRESENTER_KEY` state and its authorization helpers; handle `/api/mode` and `/api/reset` directly while retaining request-body validation and response formats. | ✅ | 2026-09-01 |
| TASK-002 | In `public/presenter.js`, delete query parsing, session storage, authorization-state controls, and key request headers; submit ordinary POST requests and retain existing failure handling. | ✅ | 2026-09-01 |
| TASK-003 | In `public/presenter.html` and `public/styles.css`, remove the presenter access-status element and its no-longer-used styles now that controls are always available. | ✅ | 2026-09-01 |

### Implementation Phase 2

- GOAL-002: Align the regression suite and user-facing instructions with keyless presenter controls.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-004 | In `test/server.test.js`, replace authorization assertions with no-header mode-change/reset behavior, retain invalid-mode validation, and retain SSE mode-event coverage. | ✅ | 2026-09-01 |
| TASK-005 | In `README.md`, replace keyed presenter URLs and key configuration/security guidance with the direct `/presenter.html` workflow and unprotected mode/reset API descriptions. | ✅ | 2026-09-01 |
| TASK-006 | Run syntax checks, `npm test`, and a repository scan for obsolete presenter-key implementation references; update this plan status after all checks pass. | ✅ | 2026-09-01 |

## 3. Alternatives

- **ALT-001**: Keep a key only on API endpoints while hiding it from the presenter UI; rejected because the browser would still need to carry the key and the stated requirement is to remove it from presenter mode.
- **ALT-002**: Leave authorization helpers unused for a future restoration; rejected because dead security configuration and code would misrepresent the actual access model.

## 4. Dependencies

- **DEP-001**: Node.js built-in `crypto`, `http`, stream, and test modules already used by the application.
- **DEP-002**: Existing browser Fetch API and EventSource behavior in `public/presenter.js`.

## 5. Files

- **FILE-001**: `server.js` owns mode/reset API behavior and startup URL output.
- **FILE-002**: `public/presenter.js` owns presenter controls and POST requests.
- **FILE-003**: `public/presenter.html` contains the presenter control markup.
- **FILE-004**: `public/styles.css` contains reusable presenter control styles.
- **FILE-005**: `test/server.test.js` verifies API validation and SSE behavior.
- **FILE-006**: `README.md` documents the direct presenter workflow and API surface.
- **FILE-007**: `plan/refactor-presenter-key-removal-1.md` records the implementation and verification state.

## 6. Testing

- **TEST-001**: `node --check server.js` and `node --check public/presenter.js` must pass.
- **TEST-002**: `npm test` must prove no-header mode changes, reset behavior, invalid-mode rejection, and SSE mode broadcasts.
- **TEST-003**: `rg -n -i 'presenter[-_ ]?key|x-presenter-key'` over active application sources and README must return no obsolete key implementation or documentation references.

## 7. Risks & Assumptions

- **RISK-001**: Any client that can reach the server can now change the mode or clear events; this is intentional because presenter-key access is no longer required.
- **ASSUMPTION-001**: The demo runs in a controlled environment where direct access to the presenter endpoint is acceptable.

## 8. Related Specifications / Further Reading

[Presenter-mode synchronization plan](feature-presenter-mode-sync-1.md)
