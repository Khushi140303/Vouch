#!/usr/bin/env python3
"""
Seed demo data for Vouch -- creates a verified company, a recruiter, and a
signed sample offer, so /verify (and the careers page badge) have real
data to check against immediately.

Run this ONCE before you demo (or again any time after resetting the db):

    python3 seed_demo_data.py             # seed (safe to re-run, won't duplicate)
    python3 seed_demo_data.py --reset     # wipe data/vouch.db first, then seed fresh

Doesn't need the server running -- it writes directly to the same
database file the API reads from.
"""
import argparse
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from backend import db
from backend.crypto_utils import (
    new_keypair, private_key_to_pem, public_key_to_pem,
    private_key_from_pem, sign_payload, sha256_hex,
)
from backend.pdf_stamp import stamp_pdf

COMPANY_NAME = "Northwind Robotics"
COMPANY_DOMAIN = "northwind-demo.xyz"
RECRUITER_EMAIL = "priya.shah@northwind-demo.xyz"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true", help="wipe data/vouch.db before seeding")
    args = parser.parse_args()

    if args.reset:
        # can't always rm on some mounts -- truncating works everywhere
        open(db.DB_PATH, "wb").close()
        print(f"reset {db.DB_PATH}")

    db.init_db()

    company = db.get_company_by_domain(COMPANY_DOMAIN)
    if company:
        print(f"'{COMPANY_NAME}' already exists as company_id={company['id']}")
    else:
        company = db.create_company(COMPANY_NAME, COMPANY_DOMAIN)
        print(f"created company_id={company['id']} ({COMPANY_NAME})")

    if not company["domain_verified"]:
        priv, pub = new_keypair()
        db.set_company_verified(company["id"], public_key_to_pem(pub), private_key_to_pem(priv))
        company = db.get_company(company["id"])
        print("domain verified (dev bypass -- no real DNS needed)")
    else:
        print("domain already verified")

    if db.is_registered_recruiter(company["id"], RECRUITER_EMAIL):
        print(f"recruiter {RECRUITER_EMAIL} already registered")
    else:
        db.add_recruiter(company["id"], "Priya Shah", RECRUITER_EMAIL, "linkedin.com/in/priyashah")
        print(f"added recruiter {RECRUITER_EMAIL}")

    sample_pdf_path = Path(__file__).parent / "demo" / "sample_offer.pdf"
    offer_id = None
    if not sample_pdf_path.exists():
        print(f"WARNING: {sample_pdf_path} not found -- skipping sample offer")
    else:
        offer_id = "VCH-" + secrets.token_hex(3).upper()
        stamped = stamp_pdf(sample_pdf_path.read_bytes(), offer_id, "http://localhost:8000")
        payload = {
            "offer_id": offer_id,
            "company_domain": company["domain"],
            "candidate_email": "alex.rivera@gmail.com",
            "role": "Software Engineer, Backend",
            "pdf_sha256": sha256_hex(stamped),
            "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        priv = private_key_from_pem(company["private_key_pem"])
        signature = sign_payload(priv, payload)
        db.save_offer(offer_id, company["id"], payload["candidate_email"], payload["role"], payload, signature)

        out_path = Path(__file__).parent / "demo" / "signed_sample_offer.pdf"
        out_path.write_bytes(stamped)
        print(f"signed a sample offer ({offer_id}) -> {out_path}")

    print()
    print("=" * 60)
    print("READY TO DEMO -- try these once the server is running:")
    print("=" * 60)
    print(f"  Careers page:    http://localhost:8080")
    print(f"  Verify page:     http://localhost:8000/verify")
    print(f"  Trust file:      http://localhost:8000/api/company/{company['id']}/trust-file")
    print()
    print(f"  On the Recruiter tab, try:  {RECRUITER_EMAIL}")
    print(f"    -> should come back VERIFIED")
    print(f"  Any other address (e.g. someone@gmail.com) will come back")
    print(f"    UNVERIFIABLE -- that's correct, it's not a registered company")
    if offer_id:
        print(f"  On the Offer Letter tab, upload:  demo/signed_sample_offer.pdf")
        print(f"    -> should come back VERIFIED")
        print(f"  Or open:  http://localhost:8000/v/{offer_id}")


if __name__ == "__main__":
    main()
