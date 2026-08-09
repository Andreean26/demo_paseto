---
goal: Interactive audience-side JWT and secure-token decoder for the live demo
version: 1.0
date_created: 2026-08-09
last_updated: 2026-08-09
owner: demo_paseto
status: 'Completed'
tags: [feature, frontend, education, jwt, paseto]
---

# Introduction

![Status: Completed](https://img.shields.io/badge/status-Completed-brightgreen)

Add an educational decoder to the audience page so participants can inspect an initial JWT, observe the visible `HS256`/`USER` claims, forge the token, and immediately compare the resulting `none`/`ADMIN` claims. For the encrypted secure token, explain its opaque structure without exposing or moving server-side key material.

## 1. Requirements & Constraints

- **REQ-001**: The audience page must provide an explicit `Decode token` action for the token currently shown in the textarea.
- **REQ-002**: A valid JWT must render its decoded header and payload as formatted JSON and display its signature segment separately.
- **REQ-003**: An initial demo JWT must produce an educational summary identifying `alg: HS256` and `role: USER`.
- **REQ-004**: A forged JWT must update the decoder and highlight `alg: none`, `role: ADMIN`, and the empty signature.
- **REQ-005**: A `v4.local` secure token must display its protocol header, opaque packed-data size, and an explanation that its encrypted payload cannot be decoded without the secret key.
- **REQ-006**: Empty, malformed, manually edited, or tampered tokens must produce a concise decoder error without breaking other audience controls.
- **SEC-001**: Decode entirely in the browser and never transmit the token or request decryption material from the server.
- **SEC-002**: Render all decoded or user-controlled values through `textContent` rather than HTML parsing.
- **CON-001**: Add no runtime dependency and preserve the repository's plain browser JavaScript structure.
- **CON-002**: Decoding must be clearly described as inspection rather than cryptographic verification.
- **GUD-001**: Reuse the existing token textarea as the single source of truth and automatically refresh decoder output after generation, forge, tamper, mode synchronization, or manual editing once the participant has opened the decoder.
- **PAT-001**: Match the existing panel, button, muted-text, responsive-grid, and monospaced-token styles in `public/styles.css`.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Implement safe client-side token inspection.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Add decoder element references and state to `public/audience.js`, including `decoderActive` so the first decode remains participant-triggered and later token changes refresh automatically. | ✅ | 2026-08-09 |
| TASK-002 | Add strict base64url byte/text helpers and JWT parsing that require exactly three segments, parse header and payload JSON, and keep the signature as untrusted text. | ✅ | 2026-08-09 |
| TASK-003 | Add secure-token inspection that recognizes `v4.local`, calculates opaque packed-data byte length, and explicitly avoids decryption. | ✅ | 2026-08-09 |
| TASK-004 | Add error handling and summaries for empty, malformed, initial, forged, and encrypted token states using text-only DOM updates. | ✅ | 2026-08-09 |

### Implementation Phase 2

- GOAL-002: Add a clear and responsive educational decoder surface.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-005 | Add a decoder panel to `public/audience.html` with an explicit button, verification disclaimer, summary, and labeled header/payload/signature output cards. | ✅ | 2026-08-09 |
| TASK-006 | Add decoder toolbar, summary-state, output-grid, card, preformatted-text, and mobile styles to `public/styles.css`. | ✅ | 2026-08-09 |
| TASK-007 | Update `README.md` so the JWT, secure-token, audience, and button instructions include the decoder workflow and its decoding-versus-verification limitation. | ✅ | 2026-08-09 |

### Implementation Phase 3

- GOAL-003: Prove the complete educational flow.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-008 | Run JavaScript syntax checks, the existing Node regression suite, plan-identifier checks, and `git diff --check`. | ✅ | 2026-08-09 |
| TASK-009 | Use the local browser to verify empty-token errors, initial JWT decoding, forged JWT updates, secure-token opacity, tampered-token handling, responsive layout, and zero console errors. | ✅ | 2026-08-09 |

## 3. Alternatives

- **ALT-001**: Send tokens to a new server decoder endpoint; rejected because JWT decoding needs no secret and transmitting tokens adds an unnecessary security and network boundary.
- **ALT-002**: Import a JWT library; rejected because base64url plus JSON parsing is sufficient for this intentionally narrow decoder and the repository has no runtime dependencies.
- **ALT-003**: Attempt to decrypt secure tokens in the browser; rejected because it would expose the server secret and contradict the security lesson.
- **ALT-004**: Decode automatically as soon as any token appears; rejected because the explicit participant action is more useful for the live teaching flow, while later automatic refresh still makes the forge comparison obvious.

## 4. Dependencies

- **DEP-001**: Browser-provided `atob`, `TextDecoder`, DOM, Fetch API, and EventSource support.
- **DEP-002**: Existing token generation, forge, tamper, and presenter-mode synchronization behavior in `public/audience.js`.
- **DEP-003**: Node.js 20 or newer for repository syntax checks and the existing `node:test` suite.

## 5. Files

- **FILE-001**: `public/audience.html` defines the educational decoder controls and output regions.
- **FILE-002**: `public/audience.js` owns local token classification, decoding, summaries, and refresh behavior.
- **FILE-003**: `public/styles.css` defines decoder layout, state colors, readable output wrapping, and mobile behavior.
- **FILE-004**: `README.md` documents how the audience uses and interprets the decoder.
- **FILE-005**: `plan/feature-audience-token-decoder-1.md` records the implementation and verification result.

## 6. Testing

- **TEST-001**: `node --check public/audience.js` must pass after decoder implementation.
- **TEST-002**: `npm test` must preserve the existing presenter authorization and SSE regression behavior.
- **TEST-003**: Browser verification must show a valid initial JWT with `HS256`, `USER`, and a non-empty signature.
- **TEST-004**: Browser verification must show a forged JWT with `none`, `ADMIN`, and an empty signature without requiring a second manual decode.
- **TEST-005**: Browser verification must show `v4.local` as encrypted opaque data and must not display decrypted claims.
- **TEST-006**: Browser verification must show friendly errors for empty or malformed token input and no console errors across all tested states.
- **TEST-007**: Browser verification at desktop and mobile widths must show readable, non-overflowing decoder output.

## 7. Risks & Assumptions

- **RISK-001**: Participants may confuse readable JWT claims with a valid token; mitigate with a persistent statement that decoding does not verify signatures.
- **RISK-002**: Long token segments can overflow narrow screens; mitigate with wrapping preformatted blocks and a single-column mobile grid.
- **RISK-003**: Automatic updates during manual editing may briefly show parsing errors; acceptable because the output accurately reflects the current textarea and does not affect token actions.
- **ASSUMPTION-001**: Audience browsers support modern baseline APIs available in the browsers already listed in the README.
- **ASSUMPTION-002**: Side-by-side historical snapshots are unnecessary because the initial manual decode followed by automatic forge refresh makes the important claim changes visible in sequence.

## 8. Related Specifications / Further Reading

[Repository README](../README.md)
[JWT specification](https://www.rfc-editor.org/rfc/rfc7519)
