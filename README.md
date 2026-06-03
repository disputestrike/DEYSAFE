# Guardian-NG — Protective Warning Engine (prototype foundation)

A civilian, rights-preserving early-warning system for Nigeria's kidnapping/banditry crisis.
**A warning system, not a targeting system.** It detects, locates, corroborates, and warns —
it never tracks individuals, never auto-acts, and never cues force.

> **Day-1 foundation:** public signals → geo-located, confidence-scored incidents → live map.
> This is the detection slice. Reporting intake, broadcast, and risk-forecast layers come next.

## The bright lines (encoded in the design, not just docs)
- **Event-centric, not person-centric.** We detect *events at places*, never score people.
- **Nothing is auto-"verified."** The maximum automatic status is `needs_human_review`. A human decides.
- **Public data only** in this layer. No private communications, telecom, financial, or biometric ingestion.
- **Corroboration raises confidence.** A single unverified source is capped low on purpose.
- **Append-only audit** of every pipeline action.

## How it works (this slice)
1. `engine/ingest.py` — gathers signals: synthetic **samples** by default; live Nigerian news **RSS** with `--live`.
2. `engine/geoparse.py` — extracts incident **type** + **location** (Nigerian gazetteer) + language. *Abstains* if either is missing.
3. `engine/corroborate.py` — clusters signals by type/place/time, scores calibrated confidence, applies the human-gate decision policy.
4. `engine/pipeline.py` — runs one pass, stores to SQLite, exports `console/incidents.json`.
5. `console/` — a Leaflet map that plots incidents by status.

## Run
```
python engine/pipeline.py            # synthetic sample data (deterministic)
python engine/pipeline.py --live     # also pull live Nigerian news feeds
```
Then view the map:
```
node console/server.js               # serves the console at http://localhost:4333
```

## Status ladder
`candidate_unverified` → `corroborated` → `needs_human_review` → **(human)** `verified`

## Honest limitations (prototype)
- The gazetteer and multi-language keywords are **starter sets** — they must be reviewed/expanded by
  native Hausa / Yoruba / Igbo / Pidgin speakers and a full LGA dataset before any real use.
- Sample data is **synthetic** and clearly labeled; it is not real events.
- Storage is local SQLite; the production target is Postgres/PostGIS (Supabase) per the architecture doc.
- No alerting/broadcast is wired yet — this is detection only.

## Next
- Public reporting intake (PWA + WhatsApp/USSD) with **reporter anonymity by design**.
- Tiered broadcast (push / WhatsApp / SMS-USSD) gated by confidence + human review.
- Place/time **risk forecast** (the "weather for danger" layer).
- NDPA (Nigeria Data Protection Act) data-handling controls + reporter threat model.
