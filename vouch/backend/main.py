"""
Vouch backend -- FastAPI app.

Run with:
    uvicorn backend.main:app --reload --port 8000

Endpoints:
    POST /api/company                          create a company, get DNS token
    POST /api/company/{id}/verify-domain        check TXT record, generate keys
    GET  /api/company/{id}/trust-file           public hiring-trust.json
    POST /api/company/{id}/recruiters           add a recruiter
    GET  /api/company/{id}/offers               list issued offers
    GET  /api/company/{id}/lookalikes           list flagged domains
    POST /api/company/{id}/monitor/scan         run the lookalike scan
    POST /api/offers                            manual offer upload -> stamp+sign
    POST /api/ats/webhook                       ATS webhook receiver -> stamp+sign
    GET  /api/offers/{id}                       public offer record (for QR scans)
    POST /api/verify/pdf                        upload PDF -> verdict
    POST /api/verify/email                      raw email or address -> verdict
    POST /api/verify/text                       message text -> scam flags

    GET  /verify                                candidate-facing verify page (4 tabs)
    GET  /v/{offer_id}                           QR-scan landing page (HTML)
    GET  /api/offers/{offer_id}/verify           JSON verdict for an offer id (used by /v/{id})
"""
import hmac
import hashlib
import io
import json
import secrets
from datetime import datetime, timezone

from pathlib import Path as _Path

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel

from backend import db, domain_checks, email_checks, scam_rules, pdf_stamp
from backend.crypto_utils import (
    new_keypair, private_key_to_pem, public_key_to_pem,
    private_key_from_pem, public_key_from_pem,
    sign_payload, verify_payload, sha256_hex,
)
from backend.domain_checks import (
    check_txt_record, classify_domain, domain_age_days, is_free_email_provider,
    generate_permutations, dns_liveness,
)
from backend.verdict import Signals, decide

BASE_URL = "http://localhost:8000"
FRONTEND_DIR = _Path(__file__).parent.parent / "frontend"

app = FastAPI(title="Vouch API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    # Without this, browsers silently hide X-Vouch-Offer-Id from JS's
    # fetch() response even though the server sends it -- the offer-issuing
    # dashboard flow needs to read it to show/download the right offer.
    expose_headers=["X-Vouch-Offer-Id"],
)


@app.on_event("startup")
def _startup():
    db.init_db()


# ---------------------------------------------------------------------
# Company / domain verification
# ---------------------------------------------------------------------

class CreateCompanyReq(BaseModel):
    name: str
    domain: str


@app.get("/api/company")
def list_companies():
    # Deliberately NOT `dict(c)` -- that row also carries private_key_pem
    # and ats_webhook_secret, neither of which belongs in a listing endpoint.
    return [
        {"id": c["id"], "name": c["name"], "domain": c["domain"],
         "domain_verified": bool(c["domain_verified"]), "created_at": c["created_at"]}
        for c in db.list_companies()
    ]


@app.post("/api/company")
def create_company(req: CreateCompanyReq):
    existing = db.get_company_by_domain(req.domain)
    if existing:
        raise HTTPException(400, "Domain already registered")
    company = db.create_company(req.name, req.domain)
    return {
        "id": company["id"],
        "name": company["name"],
        "domain": company["domain"],
        "dns_txt_record": {
            "host": f"_vouch.{company['domain']}",
            "type": "TXT",
            "value": company["verify_token"],
        },
        "instructions": "Add this TXT record at your DNS provider, then call "
                        "POST /api/company/{id}/verify-domain",
    }


@app.post("/api/company/{company_id}/verify-domain")
def verify_domain(company_id: int):
    company = db.get_company(company_id)
    if not company:
        raise HTTPException(404, "Company not found")
    if company["domain_verified"]:
        return {"domain_verified": True, "already_verified": True}

    ok = check_txt_record(company["domain"], company["verify_token"])
    if not ok:
        raise HTTPException(
            400,
            f"TXT record not found or doesn't match at _vouch.{company['domain']}. "
            f"DNS changes can take a few minutes to propagate.",
        )

    priv, pub = new_keypair()
    db.set_company_verified(company_id, public_key_to_pem(pub), private_key_to_pem(priv))
    return {"domain_verified": True}


@app.post("/api/company/{company_id}/dev-force-verify")
def dev_force_verify(company_id: int):
    """
    DEV/DEMO ONLY. Skips the real DNS TXT check so you can build and test
    locally before you've bought a domain and can actually set DNS records.
    Do NOT wire this into the frontend / leave it reachable in a real
    deployment -- it lets anyone "verify" any domain name with no proof
    of ownership. Delete this endpoint once real domain testing works.
    """
    company = db.get_company(company_id)
    if not company:
        raise HTTPException(404, "Company not found")
    if company["domain_verified"]:
        return {"domain_verified": True, "already_verified": True}
    priv, pub = new_keypair()
    db.set_company_verified(company_id, public_key_to_pem(pub), private_key_to_pem(priv))
    return {"domain_verified": True, "dev_bypass": True}


@app.get("/api/company/{company_id}/webhook-secret")
def get_webhook_secret(company_id: int):
    """
    Employer-dashboard-only value (like Stripe's webhook signing secret) --
    the ATS uses this to sign outgoing webhooks. Never expose this in the
    public trust-file.
    """
    company = db.get_company(company_id)
    if not company:
        raise HTTPException(404, "Company not found")
    return {
        "ats_webhook_secret": company["ats_webhook_secret"],
        "webhook_url": f"{BASE_URL}/api/ats/webhook",
    }


@app.get("/api/company/{company_id}/trust-file")
def trust_file(company_id: int):
    company = db.get_company(company_id)
    if not company or not company["domain_verified"]:
        raise HTTPException(404, "Company not verified")
    recruiters = db.list_recruiters(company_id)
    return {
        "company": company["name"],
        "official_domains": [company["domain"]],
        "recruiters": [
            {"name": r["name"], "email": r["email"], "linkedin": r["linkedin_url"]}
            for r in recruiters
        ],
        "public_key": company["public_key_pem"],
        "never_asks_for": ["payment", "equipment purchase", "gift cards",
                           "SSN before a signed offer"],
        "verify_url": f"{BASE_URL}/verify",
    }


# ---------------------------------------------------------------------
# Recruiters
# ---------------------------------------------------------------------

class AddRecruiterReq(BaseModel):
    name: str
    email: str
    linkedin_url: str = ""


@app.post("/api/company/{company_id}/recruiters")
def add_recruiter(company_id: int, req: AddRecruiterReq):
    company = db.get_company(company_id)
    if not company:
        raise HTTPException(404, "Company not found")

    if "@" not in req.email:
        raise HTTPException(400, "Not a valid email address")

    recruiter_domain = req.email.split("@")[-1].lower().strip()
    company_domain = company["domain"].lower()
    if recruiter_domain != company_domain:
        # This is exactly the mismatch Vouch exists to catch -- a "recruiter"
        # whose email isn't even on the company's own domain has no business
        # being trusted as one. Letting this through would mean anyone could
        # register themselves (or a Gmail address) as a "verified recruiter"
        # for a company they have no real connection to.
        raise HTTPException(
            400,
            f"Recruiter email must be on the company's verified domain "
            f"({company_domain}) -- got {recruiter_domain}. If this person "
            f"genuinely represents the company from a different domain (e.g. "
            f"an external staffing partner), that needs its own verification "
            f"path, not a plain recruiter entry.",
        )

    db.add_recruiter(company_id, req.name, req.email, req.linkedin_url)
    return {"added": True}


@app.get("/api/company/{company_id}/recruiters")
def list_recruiters(company_id: int):
    return [dict(r) for r in db.list_recruiters(company_id)]


# ---------------------------------------------------------------------
# Offer creation (shared by manual upload + ATS webhook)
# ---------------------------------------------------------------------

def _create_signed_offer(company_row, candidate_email: str, role: str, pdf_bytes: bytes) -> tuple[bytes, str]:
    if not company_row["domain_verified"]:
        raise HTTPException(400, "Company domain is not verified yet")

    offer_id = "VCH-" + secrets.token_hex(3).upper()
    stamped = pdf_stamp.stamp_pdf(pdf_bytes, offer_id, BASE_URL)
    pdf_hash = sha256_hex(stamped)

    payload = {
        "offer_id": offer_id,
        "company_domain": company_row["domain"],
        "candidate_email": candidate_email,
        "role": role,
        "pdf_sha256": pdf_hash,
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    priv = private_key_from_pem(company_row["private_key_pem"])
    signature = sign_payload(priv, payload)

    db.save_offer(offer_id, company_row["id"], candidate_email, role, payload, signature)
    return stamped, offer_id


@app.post("/api/offers")
async def create_offer_manual(
    company_id: int = Form(...),
    candidate_email: str = Form(...),
    role: str = Form(...),
    file: UploadFile = File(...),
):
    company = db.get_company(company_id)
    if not company:
        raise HTTPException(404, "Company not found")
    stamped, offer_id = _create_signed_offer(company, candidate_email, role, await file.read())
    return StreamingResponse(
        io.BytesIO(stamped),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{offer_id}.pdf"',
            "X-Vouch-Offer-Id": offer_id,
        },
    )


@app.get("/api/company/{company_id}/offers")
def list_offers(company_id: int):
    rows = db.list_offers(company_id)
    return [
        {
            "id": r["id"], "candidate_email": r["candidate_email"], "role": r["role"],
            "issued_at": r["issued_at"], "revoked": bool(r["revoked"]),
        }
        for r in rows
    ]


# ---------------------------------------------------------------------
# ATS webhook (see mock_ats/app.py for the sender side)
# ---------------------------------------------------------------------

@app.post("/api/ats/webhook")
async def ats_webhook(request: Request):
    raw_body = await request.body()
    signature = request.headers.get("X-Vouch-Signature", "")

    try:
        event = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON")

    company = db.get_company_by_domain(event.get("company_domain", ""))
    if not company:
        raise HTTPException(404, "Unknown company_domain in webhook payload")

    expected_sig = hmac.new(
        company["ats_webhook_secret"].encode(), raw_body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_sig, signature):
        raise HTTPException(401, "Invalid webhook signature")

    event_id = event.get("event_id")
    if not event_id:
        raise HTTPException(400, "Missing event_id")
    if db.webhook_event_seen(event_id):
        # idempotent replay -- return the existing offer rather than erroring
        return {"status": "duplicate_ignored", "event_id": event_id}
    db.mark_webhook_event_seen(event_id)

    if event.get("event_type") != "offer.approved":
        return {"status": "ignored", "reason": "unhandled event_type"}

    import base64
    pdf_bytes = base64.b64decode(event["offer_document"]["content_base64"])
    candidate = event["candidate"]

    stamped, offer_id = _create_signed_offer(
        company, candidate["email"], event["job"]["title"], pdf_bytes,
    )

    # store the stamped PDF so it can be retrieved/emailed; kept simple as a file
    out_path = db.DB_PATH.parent / f"offer_{offer_id}.pdf"
    out_path.write_bytes(stamped)

    return {
        "status": "signed",
        "offer_id": offer_id,
        "verify_url": f"{BASE_URL}/v/{offer_id}",
    }


@app.get("/api/offers/{offer_id}")
def get_offer_public(offer_id: str):
    offer = db.get_offer(offer_id)
    if not offer:
        raise HTTPException(404, "No record found for this offer ID")
    company = db.get_company(offer["company_id"])
    payload = json.loads(offer["payload_json"])
    email = offer["candidate_email"]
    masked = email[0] + "***@" + email.split("@")[-1] if "@" in email else "***"
    return {
        "company": company["name"],
        "role": offer["role"],
        "candidate_email_masked": masked,
        "issued_at": offer["issued_at"],
        "offer_id": offer_id,
        "pdf_sha256": payload["pdf_sha256"],
    }


# ---------------------------------------------------------------------
# Verification endpoints (the candidate-facing core)
# ---------------------------------------------------------------------

@app.post("/api/verify/pdf")
async def verify_pdf(file: UploadFile = File(...)):
    data = await file.read()
    file_hash = sha256_hex(data)

    offer = db.find_offer_by_hash(file_hash)
    if not offer:
        offer_id = pdf_stamp.extract_offer_id(data)
        offer = db.get_offer(offer_id) if offer_id else None

    if not offer:
        result = decide(Signals())
        result["offer_id"] = None
        return result

    company = db.get_company(offer["company_id"])
    payload = json.loads(offer["payload_json"])
    pub = public_key_from_pem(company["public_key_pem"])

    sig_valid = verify_payload(pub, payload, offer["signature"])
    hash_matches = (payload["pdf_sha256"] == file_hash)

    result = decide(Signals(offer_found=True, signature_valid=sig_valid, hash_matches=hash_matches))
    result["offer_id"] = offer["id"]
    result["company"] = company["name"]
    result["role"] = offer["role"]
    return result


@app.get("/api/offers/{offer_id}/verify")
def verify_offer_json(offer_id: str):
    """JSON verdict for one offer id -- same core logic as verify_pdf,
    but keyed by ID (no file upload) since the QR only encodes the ID.
    This is what /v/{offer_id}'s page fetches; kept as its own JSON
    endpoint so anything else (a script, a different frontend) can call
    it directly too."""
    offer = db.get_offer(offer_id)
    if not offer:
        result = decide(Signals())
        result["offer_id"] = offer_id
        return result

    company = db.get_company(offer["company_id"])
    payload = json.loads(offer["payload_json"])
    pub = public_key_from_pem(company["public_key_pem"])
    sig_valid = verify_payload(pub, payload, offer["signature"])

    result = decide(Signals(offer_found=True, signature_valid=sig_valid, hash_matches=True))
    result["offer_id"] = offer_id
    result["company"] = company["name"]
    result["role"] = offer["role"]
    result["note"] = "Scanned via QR — upload the PDF itself for a full tamper check."
    return result


@app.get("/v/{offer_id}", response_class=HTMLResponse)
def verify_by_qr_page(offer_id: str):
    """What scanning the QR code actually opens in a phone browser: a
    real page, not raw JSON. The page itself calls
    GET /api/offers/{offer_id}/verify via fetch() and renders the result --
    offer_id lives in the URL, so the same static HTML works for every offer."""
    return HTMLResponse((FRONTEND_DIR / "offer_verify.html").read_text())


@app.get("/verify", response_class=HTMLResponse)
def verify_page():
    """The candidate-facing verify page: upload an offer / paste an email /
    check a recruiter / paste a message. This is what the badge and every
    trust-file link point to."""
    return HTMLResponse((FRONTEND_DIR / "verify.html").read_text())


@app.get("/app", response_class=HTMLResponse)
def combined_app_page():
    """The single-page combined dashboard: candidate checks (email/PDF/text/
    offer-id) plus the company-setup flow (create, verify, add recruiters,
    issue offers, scan lookalikes), all against this same running API. Handy
    for building/demoing without juggling curl and /docs."""
    return HTMLResponse((FRONTEND_DIR / "vouch-app.html").read_text())


class VerifyEmailReq(BaseModel):
    raw_email: str | None = None
    sender_address: str | None = None
    # Optional companion to sender_address: the message body/subject text, for
    # callers that can't get the full raw source (e.g. a browser extension
    # reading a rendered inbox) but can still read the sender address and the
    # visible text. Ignored when raw_email is given (its own body is used).
    body_text: str | None = None


@app.post("/api/verify/email")
def verify_email(req: VerifyEmailReq):
    sig = Signals()

    if req.raw_email:
        parsed = email_checks.analyze_raw_email(req.raw_email)
        from_domain = parsed["from_domain"]
        sender_email = parsed["from_address"]
        sig.dmarc, sig.dkim, sig.spf = parsed["dmarc"], parsed["dkim"], parsed["spf"]
        sig.reply_to_mismatch = parsed["reply_to_mismatch"]
        text_hits = scam_rules.scan_text(parsed["body"])
    elif req.sender_address:
        sender_email = req.sender_address.lower()
        from_domain = sender_email.split("@")[-1].lower()
        # No raw source here (no Authentication-Results header to read), but if
        # the caller could still grab the visible body/subject text -- e.g. a
        # Gmail-inbox extension scraping the rendered message -- scan it for
        # scam patterns just like the full-source path does.
        text_hits = scam_rules.scan_text(req.body_text) if req.body_text else []
    else:
        raise HTTPException(400, "Provide raw_email or sender_address")

    sig.text_flags = text_hits

    if not from_domain:
        # We had an email to look at but couldn't find a usable From address in it
        # (e.g. someone pasted just the message body, not the full email source).
        # Don't crash -- still run the free-text scam checks so obvious red flags
        # (payment requests, gift cards, urgency, etc.) still surface.
        result = decide(sig)
        result["from_domain"] = None
        result["reasons"] = [
            "Couldn't find a sender address in this email -- paste the FULL email "
            "source (From, Subject, and Authentication-Results headers included), "
            "not just the message body, for a real check."
        ] + result.get("reasons", [])
        result["signals"] = {
            "domain_status": None, "domain_imitates": None, "domain_age_days": None,
            "dmarc": sig.dmarc, "dkim": sig.dkim, "spf": sig.spf, "is_free_email": None,
        }
        return result

    sig.is_free_email = is_free_email_provider(from_domain)

    companies = db.list_companies()
    official_domains = [c["domain"] for c in companies if c["domain_verified"]]
    classification = classify_domain(from_domain, official_domains)
    sig.domain_status = classification["status"]
    sig.domain_imitates = classification["imitates"]

    matched_company = next(
        (c for c in companies if c["domain"] == classification.get("imitates")
         or c["domain"] == from_domain),
        None,
    )
    if matched_company:
        sig.company_known = True
        if sender_email:
            sig.recruiter_registered = db.is_registered_recruiter(
                matched_company["id"], sender_email
            )

    sig.domain_age_days = domain_age_days(from_domain)

    result = decide(sig)
    result["from_domain"] = from_domain
    result["signals"] = {
        "domain_status": sig.domain_status,
        "domain_imitates": sig.domain_imitates,
        "domain_age_days": sig.domain_age_days,
        "dmarc": sig.dmarc, "dkim": sig.dkim, "spf": sig.spf,
        "is_free_email": sig.is_free_email,
    }
    return result


class VerifyTextReq(BaseModel):
    text: str


@app.post("/api/verify/text")
def verify_text(req: VerifyTextReq):
    hits = scam_rules.scan_text(req.text)
    result = decide(Signals(text_flags=hits))
    result["flags"] = hits
    if result["verdict"] == "unverifiable" and not hits:
        # Text alone never has a sender/domain to check, so "no red flags" here
        # is not the same claim as "verified" -- say exactly that instead of
        # the generic can't-verify reason used elsewhere.
        result["reasons"] = [
            "No scam patterns found in this text, but this check can't vouch "
            "for who actually sent it. For that, check the sender's email or "
            "recruiter address on the Email or Recruiter tab."
        ]
    return result


# ---------------------------------------------------------------------
# Look-alike domain monitor
# ---------------------------------------------------------------------

@app.post("/api/company/{company_id}/monitor/scan")
def run_monitor_scan(company_id: int):
    company = db.get_company(company_id)
    if not company:
        raise HTTPException(404, "Company not found")

    candidates = generate_permutations(company["domain"])
    flagged = []
    for candidate in candidates:
        liveness = dns_liveness(candidate)
        if not liveness["resolves"]:
            continue  # not registered / doesn't resolve -- not currently a threat
        age = domain_age_days(candidate)
        risk = "high" if liveness["has_mx"] else "medium"
        db.upsert_lookalike(company_id, candidate, liveness["has_mx"], age, risk, "permutation")
        flagged.append({"domain": candidate, "has_mx": liveness["has_mx"],
                        "registered_days_ago": age, "risk": risk})

    return {"scanned": len(candidates), "flagged": flagged}


@app.get("/api/company/{company_id}/lookalikes")
def get_lookalikes(company_id: int):
    return [dict(r) for r in db.list_lookalikes(company_id)]
