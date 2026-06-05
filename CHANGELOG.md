# Changelog

All notable changes to DeySafe / SHIELD will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Entries map to the CAPA register and the traceability matrix (`docs/TRACEABILITY.md`).

## [Unreleased]

_No tagged release yet — full history grouped here. Each entry references its originating commit (and CAPA id where applicable)._

### Added
- Initial DeySafe / SHIELD prototype — civilian protective-warning platform; round-robin Cerebras AI, FindMe + broadcast, route-on-map (Railway-ready) (748af99)
- **Phase 0 — trust core**: operator auth (fail-closed), abuse controls, public/operator PII split, immutable incident UUIDs, XSS hardening, demo-mode gating, geocode honesty (ee5087a)
- **Phase 1–4 build**: response/SOS loop, life-saving metrics, source reputation + coordinated-burst quarantine, signed rotating beacons, ingest scheduler (ebbf387)
- North Star traceability/validation matrix + automated pre-release gate `validate.py` (7f4ab6c)
- PostgreSQL dual-mode storage (Railway-ready) with graceful SQLite fallback — CAPA #13 (1f4f278)
- Free-text geocoded locations everywhere; report→incident pipeline geocodes any typed town onto the map — CAPA #1/#2 (0e18694, f2376bc)
- Operator-triggered live scraping of public news; geofenced area report + AI reads the live news — CAPA #3/#4/#5 (8fc9a5e, f7ec474)
- Venn-diagram triangulation for FindMe, the find-people centerpiece — CAPA #8 (0b6f24e)
- WakaSafe route voice + nav-style narrative and Tesla-style route detail — CAPA #9 (25c7f02, 9083dd2)
- Voice input (speech-to-text) and AI natural-language intake — CAPA #14/#16 (a4734d1, 5ee446a)
- Proactive proximity warnings, Waze/Google-style — CAPA #15 (995c79f)
- SOS redesign (Automatic / Hold-and-Speak); policing accountability + community channels — CAPA #18/#19/#20 (4028826, aa41a79)
- Strava movement layer — heading cones + danger heatmap — CAPA #21 (d9fc044)
- SMS + USSD reach for basic phones (Ushahidi-style) — CAPA #22 (f367c1e)
- Bluetooth crowd-mesh "find people offline" backend (AirTag model) — CAPA #23 (ce09561)
- Privacy-first locate + reset map control; voice talk-back (TTS) on area reports — CAPA #6/#7 (74c49dd, 553a249)
- Automated incident decay + visible RED state — CAPA #10/#11 (ccee224)

### Changed
- Incident markers fade with age — decay made visible — CAPA #12 (2968520)
- Traceability crosswalk kept in lockstep with the gate suite (49/49 → 56/56) (93a65c1, c4e6992)

### Fixed
- Map "won't center on me / won't move" — CAPA #17 (0d365f3)
- Desktop no-scroll (home view always rendering) + tap-the-map-to-report overlay (4fccf6e)
- Kill-switch service worker + stop caching — fixes a stale app served from browser cache (566d910)
- `metrics.py` clock anchored to real "now" — fixes date-stale active-alert counts (ea1fb8f)

### Security
- Fail-**closed** operator auth, public/operator PII split (redacted public flyer), immutable incident UUIDs, XSS hardening, demo-mode gating — Phase 0 trust core (ee5087a)
- Signed rotating beacon envelope with HMAC + replay guard — BLE-01 (ebbf387)

### Documentation
- README rewrite for DeySafe (current product, features, how to run, honest scope) (f24db60)
- Exhaustive audit register (all 4 audit sources) + synthesized feedback/fix plan (62c5673, df1e7be)

[Unreleased]: https://github.com/disputestrike/DEYSAFE/compare/748af99...HEAD
