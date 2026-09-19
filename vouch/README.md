# Vouch — trust in the hiring funnel

A working starter for the "trust in the hiring funnel" hackathon theme.
Employers cryptographically sign offer letters and publish a registry of
real recruiters/domains; candidates check any offer, email, or recruiter
in seconds and get **Verified / Likely scam / Can't verify** with plain-English
reasons — never a bare AI score.

Every module below has a self-test (`python backend/<module>.py`) and the
whole system has an end-to-end sanity script (`demo/run_demo.py`). Everything
in this repo has been run and passes as of the last commit.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# terminal 1
uvicorn backend.main:app --reload --port 8000

# terminal 2 — proves the whole system works end to end
python demo/run_demo.py

# interactive API docs (great for building the frontend against)
open http://localhost:8000/docs
```

## What's built (backend, fully working)

| File | What it does |
|---|---|
| `backend/crypto_utils.py` | Ed25519 keygen, canonical-JSON signing/verification, SHA-256 |
| `backend/pdf_stamp.py` | Stamps a QR code + verify footer onto the last page of an offer PDF |
| `backend/domain_checks.py` | Look-alike domain detection (homoglyphs + fuzzy match), TXT-record domain-ownership check, RDAP domain age, permutation generator, DNS liveness |
| `backend/email_checks.py` | Parses raw email source: SPF/DKIM/DMARC results, From/Reply-To mismatch, body extraction |
| `backend/scam_rules.py` | Regex rules for payment requests, check scams, gift cards, early PII asks, off-platform chat, urgency, "too good to be true" pay |
| `backend/verdict.py` | Combines every signal into one verdict + human-readable reasons. **Unknown company → "can't verify," never "scam."** |
| `backend/db.py` | SQLite: companies, recruiters, offers, look-alike domains, webhook idempotency |
| `backend/main.py` | FastAPI app wiring all of the above into HTTP endpoints |
| `mock_ats/send_offer.py` | CLI that fires a signed webhook exactly like a real ATS (Greenhouse/Lever-shaped payload) |
| `demo/run_demo.py` | End-to-end script — run this before you demo to judges |

## API reference

Full interactive docs at `/docs` once the server is running. Key endpoints:

**Employer side**
- `POST /api/company` — sign up, get a DNS TXT token
- `POST /api/company/{id}/verify-domain` — real DNS check (needs a domain you control)
- `POST /api/company/{id}/dev-force-verify` — **dev/demo only**, skips DNS so you can build before you own a domain. Delete before anything resembling production.
- `POST /api/company/{id}/recruiters` — add an authorized recruiter
- `GET /api/company/{id}/trust-file` — the public `hiring-trust.json` content
- `GET /api/company/{id}/webhook-secret` — the HMAC secret your ATS/mock-ATS signs with
- `POST /api/company/{id}/monitor/scan` — run the look-alike domain scan
- `GET /api/company/{id}/lookalikes` — flagged domains

**Offers**
- `POST /api/offers` — upload a PDF (multipart) → get back a stamped, signed PDF
- `POST /api/ats/webhook` — what an ATS calls when an offer is approved (HMAC-signed, idempotent, replay-proof)
- `GET /v/{offer_id}` — what scanning the QR code opens
- `GET /api/offers/{offer_id}` — public offer record (masked candidate email)

**Verification (the candidate-facing core)**
- `POST /api/verify/pdf` — upload any PDF → verdict
- `POST /api/verify/email` — paste raw email source (or just a sender address) → verdict
- `POST /api/verify/text` — paste message text → scam-pattern flags

## Running the mock-ATS demo

```bash
# 1. create + verify a company, add a recruiter (see demo/run_demo.py for the exact calls,
#    or use /docs interactively)
# 2. grab its webhook secret
curl http://localhost:8000/api/company/1/webhook-secret

# 3. fire a webhook exactly like a real ATS would on "offer approved"
python mock_ats/send_offer.py --company-domain northwind.xyz \
  --job "Software Engineer" --name "Alex Rivera" --email alex.rivera@gmail.com \
  --secret <paste the webhook secret>

# response includes a verify_url -- open it, or hit GET /v/{offer_id}
```

## Built and working (frontend)

These are served directly by the FastAPI app -- no separate frontend
build step needed, and no CORS issues since they're same-origin:

- **`GET /verify`** (`frontend/verify.html`) -- the candidate-facing page:
  four tabs (upload offer / paste email / check recruiter / paste text),
  one result card (green/red/gray) with the reasons list. This is the
  screen you'll have open on stage most of the time. Supports
  `?tab=pdf|email|recruiter|text` deep links.
- **`GET /v/{offer_id}`** (`frontend/offer_verify.html`) -- what scanning
  the QR code on a stamped offer actually opens: a real result page (not
  raw JSON), pulling from `GET /api/offers/{offer_id}/verify`.
- **`careers_page/index.html` + `careers_page/badge.js`** -- a demo
  "Northwind Robotics" careers page with the Vouch trust badge embedded
  in the footer, showing exactly what a company would add to their real
  site. Serve it separately (`python3 -m http.server 8080` inside
  `careers_page/`) alongside the API.

## Still to build

1. **Mock ATS page** — a form (job title / candidate name+email) with an
   "Approve Offer" button that calls the webhook flow (`mock_ats/send_offer.py`
   already does this from the CLI; a page just wraps it visually).
2. **Employer dashboard** — DNS setup step, recruiter table, offers list,
   look-alike domains table, trust-file preview. Nothing here is complex;
   it's all reading from endpoints that already exist and work
   (`GET /api/company/{id}/offers`, `/lookalikes`, `/recruiters`, `/trust-file`).

CORS is currently open for `*` in `backend/main.py` for ease of embedding
the badge anywhere during the hackathon -- tighten that before anything
public.

## Known limitations (say these before judges ask)

- Domain age/CT-log/RDAP lookups need real internet + real registered
  domains; they degrade to "unknown" gracefully offline, which is fine for
  local dev but means the monitor needs real domains bought before the demo.
- `dev-force-verify` bypasses real domain ownership proof — it exists only
  so the team can build before buying domains; wire the frontend to the
  real `verify-domain` (DNS TXT) endpoint once you've bought your demo
  domains, and stop exposing the bypass endpoint publicly.
- SQLite + a single encrypted-at-rest-in-practice-not-yet private key per
  company is fine for a hackathon; say "swap for Postgres + KMS" if asked
  about production hardening.
