# Deploying DeySafe / SHIELD to Railway

This prototype is a **pure-Python (standard-library-only)** web app — one web process,
no build step, no external services required to boot. Storage is SQLite.

## Steps
1. Push this `guardian-ng/` folder to a GitHub repo (or run `railway up` from it).
2. Railway → **New Project → Deploy from repo** (root = `guardian-ng`).
3. Railway auto-detects Python and runs the `Procfile`: `web: python engine/api.py`.
4. The server binds `0.0.0.0:$PORT` automatically. Railway gives you a public HTTPS URL.
5. **(Recommended)** Add a **Volume** mounted at `data/` so the SQLite DB survives
   redeploys. Without it, data resets each deploy (fine for a demo).

## Turn ON real AI
Railway → **Variables** → add ONE of:
- `CEREBRAS_API_KEY` = <a FRESH Cerebras key>   ← you have this
- or `GEMINI_API_KEY` / `GROQ_API_KEY` (free tiers)

Then real LLM incident extraction is live. Test:
`POST /api/classify  {"text": "Gunmen abducted 15 students in Kankara, took them north in a white Hilux"}`

## What is live after deploy
- Public installable **PWA**: map, area risk (GREEN/YELLOW/ORANGE/RED), anonymous
  reporting + corroboration, **FindMe** (missing persons / groups / sighting-tightening /
  shareable flyer), **WakaSafe** route check.
- **SHIELD** operator console at `/review.html` — verify → fires a public alert + banner.
- With an AI key: real multi-language (English/Hausa/Yoruba/Pidgin) extraction.

## NOT live yet (needs more keys / build)
- Phone **push / WhatsApp / SMS** (need OneSignal / Meta / Africa's Talking keys)
- Satellite, 72-hour forecast, user accounts, full 774-LGA geo data, scheduled scrapers
- Production DB — target is Postgres/PostGIS; this prototype uses SQLite

## ⚠️ BEFORE ANY PUBLIC LAUNCH — read this
The app seeds **synthetic sample incidents/alerts** for demonstration. A public safety
app that shows **fake alerts can cause real harm** (panic, mistrust, people avoiding
safe roads). Deploy this as a **labeled demo / staging** first. Go *public* only after:
(1) sample data is replaced by **live, human-verified** data, (2) "developing/unverified"
labels are clear, (3) the prototype banner is removed only when the pipeline is real.
