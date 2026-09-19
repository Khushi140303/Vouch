"""
End-to-end sanity check for the whole Vouch flow. Run this any time you
want to confirm the whole system still works -- especially right before
you demo it to judges.

Usage:
    1. In one terminal: uvicorn backend.main:app --port 8000
    2. In another:      python demo/run_demo.py

It exercises, against the real running server:
    1. Employer signup + (dev-bypass) domain verification
    2. Recruiter registry
    3. Signing a genuine offer letter (manual upload path)
    4. Verifying that genuine offer -> VERIFIED
    5. Tampering with it and verifying again -> SCAM (hash mismatch)
    6. The ATS webhook path (mock ATS -> auto-signed offer)
    7. A scam email impersonating the company via a look-alike domain -> SCAM
    8. A genuine recruiter email from the real domain -> VERIFIED
    9. An email from a company that never joined Vouch -> UNVERIFIABLE (not "scam")
    10. Free-text scam pattern detection
    11. The look-alike domain monitor

Exits non-zero if any check fails, so it can be dropped into a CI step
or just run by hand between build sessions.
"""
import base64
import hashlib
import hmac
import io
import json
import secrets
import sys
import time
from pathlib import Path

import httpx
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas

BASE_URL = "http://localhost:8000"
DEMO_DIR = Path(__file__).parent
PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = ""):
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    (PASS if condition else FAIL).append(name)


def make_sample_pdf(path: Path):
    c = canvas.Canvas(str(path), pagesize=(612, 792))
    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, 720, "Demo Robotics - Offer of Employment")
    c.setFont("Helvetica", 12)
    c.drawString(72, 680, "Candidate: Alex Rivera")
    c.drawString(72, 660, "Role: Software Engineer, Backend")
    c.drawString(72, 640, "Salary: $120,000 / year")
    c.save()


def tamper_pdf(src: Path, dst: Path):
    reader = PdfReader(str(src))
    writer = PdfWriter()
    page = reader.pages[0]
    overlay_buf = io.BytesIO()
    c = canvas.Canvas(overlay_buf, pagesize=(612, 792))
    c.setFillColorRGB(1, 1, 1)
    c.rect(70, 634, 300, 14, fill=1, stroke=0)
    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 12)
    c.drawString(72, 640, "Salary: $500,000 / year")
    c.save()
    overlay_buf.seek(0)
    page.merge_page(PdfReader(overlay_buf).pages[0])
    writer.add_page(page)
    for p in reader.pages[1:]:
        writer.add_page(p)
    with open(dst, "wb") as f:
        writer.write(f)


def main():
    client = httpx.Client(base_url=BASE_URL, timeout=15)
    suffix = secrets.token_hex(3)
    domain = f"demo-{suffix}.xyz"

    print(f"=== Vouch end-to-end demo (company domain: {domain}) ===\n")

    # 1. signup + dev-bypass domain verification
    r = client.post("/api/company", json={"name": "Demo Robotics", "domain": domain})
    check("Create company", r.status_code == 200, r.text)
    company_id = r.json()["id"]

    r = client.post(f"/api/company/{company_id}/dev-force-verify")
    check("Dev-force-verify domain", r.status_code == 200 and r.json()["domain_verified"])

    # 2. recruiter registry
    recruiter_email = f"priya.shah@{domain}"
    r = client.post(f"/api/company/{company_id}/recruiters",
                    json={"name": "Priya Shah", "email": recruiter_email})
    check("Add recruiter", r.status_code == 200)

    webhook_secret = client.get(f"/api/company/{company_id}/webhook-secret").json()["ats_webhook_secret"]

    # 3+4. sign a genuine offer, verify it
    sample_pdf = DEMO_DIR / "sample_offer.pdf"
    if not sample_pdf.exists():
        make_sample_pdf(sample_pdf)

    r = client.post(
        "/api/offers",
        data={"company_id": company_id, "candidate_email": "alex.rivera@gmail.com",
              "role": "Software Engineer, Backend"},
        files={"file": ("offer.pdf", sample_pdf.read_bytes(), "application/pdf")},
    )
    check("Sign genuine offer", r.status_code == 200, r.text)
    stamped_pdf = r.content
    offer_id = r.headers.get("x-vouch-offer-id")
    (DEMO_DIR / "stamped_offer.pdf").write_bytes(stamped_pdf)

    r = client.post("/api/verify/pdf", files={"file": ("offer.pdf", stamped_pdf, "application/pdf")})
    check("Verify genuine offer -> verified", r.status_code == 200 and r.json()["verdict"] == "verified",
          r.text)

    # 5. tamper, verify again
    tampered_path = DEMO_DIR / "tampered_offer.pdf"
    tamper_pdf(DEMO_DIR / "stamped_offer.pdf", tampered_path)
    r = client.post("/api/verify/pdf", files={"file": ("offer.pdf", tampered_path.read_bytes(), "application/pdf")})
    check("Verify tampered offer -> scam", r.status_code == 200 and r.json()["verdict"] == "scam", r.text)

    # 6. ATS webhook path
    payload = {
        "event_type": "offer.approved", "event_id": f"evt_demo_{int(time.time() * 1000)}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "company_domain": domain,
        "job": {"id": "job_1", "title": "Product Manager"},
        "candidate": {"id": "c1", "first_name": "Jamie", "last_name": "Lee", "email": "jamie.lee@outlook.com"},
        "offer_document": {"filename": "offer.pdf",
                           "content_base64": base64.b64encode(sample_pdf.read_bytes()).decode()},
    }
    body = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    r = client.post("/api/ats/webhook", content=body,
                    headers={"Content-Type": "application/json", "X-Vouch-Signature": sig})
    check("ATS webhook signs offer automatically", r.status_code == 200 and r.json()["status"] == "signed", r.text)

    r_replay = client.post("/api/ats/webhook", content=body,
                           headers={"Content-Type": "application/json", "X-Vouch-Signature": sig})
    check("Webhook replay is ignored, not double-signed",
          r_replay.status_code == 200 and r_replay.json()["status"] == "duplicate_ignored")

    bad_sig_resp = client.post("/api/ats/webhook", content=body,
                               headers={"Content-Type": "application/json", "X-Vouch-Signature": "0" * 64})
    check("Forged webhook signature is rejected (401)", bad_sig_resp.status_code == 401)

    # 7. scam email impersonating the company via look-alike domain
    lookalike_domain = domain.replace("demo-", "demo-careers-")
    scam_email = f"""From: "Demo Recruiting" <hr@{lookalike_domain}>
Reply-To: payouts@gmail.com
Subject: Your offer - action needed
Authentication-Results: mx.google.com; dkim=fail header.d={lookalike_domain}; spf=fail smtp.mailfrom={lookalike_domain}; dmarc=fail header.from={lookalike_domain}
Content-Type: text/plain

Congratulations! Please pay a $200 equipment fee via gift cards within
24 hours and send your SSN for payroll setup.
"""
    r = client.post("/api/verify/email", json={"raw_email": scam_email})
    check("Scam look-alike-domain email -> scam", r.status_code == 200 and r.json()["verdict"] == "scam", r.text)

    # 8. genuine recruiter email
    real_email = f"""From: "Priya Shah" <{recruiter_email}>
Subject: Your offer letter
Authentication-Results: mx.google.com; dkim=pass header.d={domain}; spf=pass smtp.mailfrom={domain}; dmarc=pass header.from={domain}
Content-Type: text/plain

Congratulations! Please find your official offer letter attached.
"""
    r = client.post("/api/verify/email", json={"raw_email": real_email})
    check("Genuine registered-recruiter email -> verified",
          r.status_code == 200 and r.json()["verdict"] == "verified", r.text)

    # 9. company never on Vouch at all
    unknown_email = """From: "Some Recruiter" <jobs@totally-unrelated-company.com>
Subject: Job opportunity
Content-Type: text/plain

Hi, we would like to interview you for a role.
"""
    r = client.post("/api/verify/email", json={"raw_email": unknown_email})
    check("Unknown (non-Vouch) company -> unverifiable, NOT scam",
          r.status_code == 200 and r.json()["verdict"] == "unverifiable", r.text)

    # 10. free-text scam pattern detection
    r = client.post("/api/verify/text", json={
        "text": "Please send your bank account details and a $150 deposit via gift card to begin.",
    })
    check("Free-text scam pattern detection fires", r.status_code == 200 and len(r.json()["flags"]) >= 2, r.text)

    # 11. look-alike domain monitor
    r = client.post(f"/api/company/{company_id}/monitor/scan")
    check("Look-alike domain monitor runs without error", r.status_code == 200, r.text)
    print(f"      (scanned {r.json()['scanned']} permutations, "
          f"{len(r.json()['flagged'])} currently registered/live)")

    print(f"\n=== {len(PASS)} passed, {len(FAIL)} failed ===")
    if FAIL:
        print("Failed checks:", ", ".join(FAIL))
        sys.exit(1)


if __name__ == "__main__":
    main()
