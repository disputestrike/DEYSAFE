# Data Protection Impact Assessment — DeySafe / SHIELD

**Regulation:** Nigeria Data Protection Act 2023 (NDPA) and the NDPR.
**System:** DeySafe (civilian early-warning + find-people PWA) and SHIELD (operator console).
**Bright line:** DeySafe is a **public-safety warning** system, not a surveillance or
targeting system. It warns people away from danger; it never directs force, never
auto-dispatches, and keeps a human in the loop for every public RED alert.

> This DPIA is a living document. Update it whenever a new data type, processor, or
> cross-border transfer is introduced. Owner: the DeySafe data controller.

---

## 1. Processing overview

| Question | Answer |
|---|---|
| Why is data processed? | To warn the public about verified threats and to help locate missing people. The lawful bases are **consent** (alert subscriptions, citizen accounts), **vital interests** (responding to an imminent threat to life), and **legitimate interest** (aggregated, de-identified safety analytics). |
| Who are the data subjects? | Citizens who report danger, subscribe to alerts, raise an SOS, register a missing person, or start a SafeMeet session; and registered operators/responders. |
| Is processing high-risk? | Yes — it can involve location and threat data in a kidnapping context, so retaliation risk is the headline concern and drives the mitigations below. |

## 2. Data inventory

| Data | Where | Sensitivity | Retention | Notes |
|---|---|---|---|---|
| Community reports (type, place, text, optional media ref) | `signals`/`incidents` | Medium | Status-based decay (candidate 48h → verified 240h); auto-aged off the public map | Reporter identity is **not** stored; only an irreversible hashed handle for abuse limiting |
| Reporter network metadata | logs | Medium | Not stored raw | **IP is truncated** (IPv4 /24, IPv6 /48) before logging (P0-09) |
| Alert subscribers (phone/endpoint, state) | `subscribers` | High (contact PII) | Until opt-out/erasure | `consent_at` recorded; `address_hash` lets us unsubscribe/erase without a plaintext scan |
| Citizen accounts (phone hash, first name, language) | `citizen_users` | High | Until erasure | Phone stored as a **hash**; sessions are device-scoped tokens |
| Safety Vault guardians / trusted contacts | `trusted_contacts`, vault | High | Until erasure | **Encrypted at rest** (`DEYSAFE_VAULT_KEY`) |
| SOS events | `sos_events` | High | Status-based; closed events expire | Anonymous; owner-token gated; duress PIN supported |
| SafeMeet sessions + check-ins | `safemeet_*` | High | Session lifetime + short tail | Pre-incident protection; duress check-in escalates silently |
| Evidence media | Cloudflare R2 (optional) | High | Per bucket lifecycle | Upload is **type/size limited + quota'd + auth-gated**; only a custody hash is kept when R2 is unconfigured |
| Operator/responder roster | `DEYSAFE_OPERATORS` env, `responders` | Medium | Operational | Passwords are **PBKDF2** hashes; never plaintext |
| Audit trail | `audit` | Low (no PII) | Operational | Hash-chained; records the **actual operator identity**, not a generic literal (P1-06) |

## 3. Necessity & proportionality

- **Data minimisation:** community reports are anonymous; citizen phone numbers are
  stored as hashes; precise device GPS for "check my area" is computed **on-device**
  and never sent to the server (privacy bright line).
- **Purpose limitation:** data is used only to warn and to locate. It is never sold,
  never used for advertising, and never compiled into per-person profiles.
- **No targeting:** the system produces area-level warnings (GREEN→RED). It does not
  identify or track individuals, and RED is reserved for human-verified threats.

## 4. Data-subject rights (how each is honoured)

| Right | Mechanism |
|---|---|
| Withdraw consent | `POST /api/unsubscribe` (alert opt-out) |
| Erasure / "right to be forgotten" | `POST /api/erasure` (`confirm=ERASE`) — hard-deletes subscriber, trusted-contact, SOS, citizen, and session records by any identifier; admin-initiated or citizen self-service |
| Access / rectification | Citizen profile (verified session); operator request via the controller |
| Retention limits | Automatic status-based decay + `POST /api/retention` (admin, `confirm=APPLY_RETENTION`) for a manual purge with a dry-run preview |

## 5. Security controls (implemented)

- **Transport/headers:** HSTS, strict CSP, X-Frame-Options, Permissions-Policy, and a
  CORS **allow-list** (`DEYSAFE_ALLOWED_ORIGINS`).
- **Auth:** operator passwords are PBKDF2 (200k iterations, per-user salt); sessions are
  signed; query-string tokens are rejected (header-only).
- **RBAC:** `viewer < reviewer < verifier < admin`; only a *verifier* can publish a RED
  alert, only an *admin* can purge or erase.
- **Two-person integrity:** `DEYSAFE_DUAL_APPROVAL` requires a second, different operator
  to confirm a public RED alert.
- **Encryption at rest:** Safety Vault contacts (`DEYSAFE_VAULT_KEY`).
- **Abuse/forgery:** inbound SMS/USSD webhooks require a shared secret; media presign is
  quota'd and auth-gated; reporter floods share one hashed reputation bucket.
- **Fail-closed:** `DEYSAFE_REQUIRE_POSTGRES=1` refuses an unsafe SQLite fallback in prod.

## 6. Risks & mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Reporter is identified and retaliated against | Medium | Severe | No reporter identity stored; IP truncated; Tor/VPN guidance; on-device location |
| False/malicious report triggers panic | Medium | High | Single unverified report capped at YELLOW; human verify required for RED; two-person confirm; reputation + quarantine |
| Subscriber list leaks | Low | High | `data/` never committed; contact PII minimised; vault encrypted; erasure endpoint |
| Operator account compromise | Low | High | PBKDF2, RBAC, two-person RED approval, hash-chained audit with real identity |
| Spoofed provider webhook injects reports | Medium | High | Shared-secret verification on `/api/sms` + `/api/ussd` |

## 7. Residual risk & sign-off

With the controls above, residual risk is assessed **LOW–MEDIUM** and acceptable for a
controlled launch, conditional on: (a) `DEMO_MODE=0`, real Postgres, and the security
flags set per `DEPLOY.md §3b`; (b) a named data controller and an incident-response
contact; (c) native-language review of citizen-facing copy. SafeMeet and FindMe location
features remain opt-in and human-in-the-loop.

_Reviewed by: ____________________  Date: ____________  Next review: on any new data type._
