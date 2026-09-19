"""
Mock ATS: simulates the moment a real ATS (Greenhouse, Lever, iCIMS)
fires an "offer approved" webhook. Run this as a CLI to demo the
webhook flow without needing real ATS sandbox access.

Usage:
    python mock_ats/send_offer.py --job "Software Engineer" \
        --name "Alex Rivera" --email alex.rivera@gmail.com

The signature scheme (HMAC-SHA256 over the raw request body) is the
same pattern Stripe and GitHub webhooks use, so it's a credible stand-in
for what a real ATS integration would look like.
"""
import argparse
import base64
import hashlib
import hmac
import json
import time
from pathlib import Path

import httpx

VOUCH_WEBHOOK_URL = "http://localhost:8000/api/ats/webhook"
DEMO_PDF_PATH = Path(__file__).parent.parent / "demo" / "sample_offer.pdf"


def sign(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def build_payload(company_domain: str, job_title: str, name: str, email: str) -> dict:
    with open(DEMO_PDF_PATH, "rb") as f:
        pdf_b64 = base64.b64encode(f.read()).decode()

    first, *rest = name.split(" ")
    last = rest[-1] if rest else ""

    return {
        "event_type": "offer.approved",
        "event_id": f"evt_{int(time.time() * 1000)}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "company_domain": company_domain,
        "job": {"id": "job_4471", "title": job_title},
        "candidate": {"id": "cand_1", "first_name": first, "last_name": last, "email": email},
        "offer_document": {"filename": "offer_letter.pdf", "content_base64": pdf_b64},
    }


def send(company_domain: str, job_title: str, name: str, email: str, webhook_secret: str):
    payload = build_payload(company_domain, job_title, name, email)
    body = json.dumps(payload, separators=(",", ":")).encode()
    signature = sign(body, webhook_secret)

    resp = httpx.post(
        VOUCH_WEBHOOK_URL,
        content=body,
        headers={"Content-Type": "application/json", "X-Vouch-Signature": signature},
        timeout=15,
    )
    print(f"-> POST {VOUCH_WEBHOOK_URL}")
    print(f"<- {resp.status_code} {resp.text}")
    return resp


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mock ATS offer-approval webhook sender")
    parser.add_argument("--company-domain", default="northwind.xyz")
    parser.add_argument("--job", default="Software Engineer, Backend")
    parser.add_argument("--name", default="Alex Rivera")
    parser.add_argument("--email", default="alex.rivera@gmail.com")
    parser.add_argument("--secret", required=True,
                        help="The company's ats_webhook_secret (get it from the Vouch DB/dashboard)")
    args = parser.parse_args()

    send(args.company_domain, args.job, args.name, args.email, args.secret)
