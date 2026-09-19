"""
Combines every individual signal (domain classification, domain age,
email auth results, scam-text flags, recruiter registry membership,
signature/hash checks) into ONE of three verdicts:

    verified      - strong positive evidence, safe to trust
    scam          - a hard-fail signal fired; treat as malicious
    unverifiable  - no strong evidence either way; caution, not proof

The three-way split matters: a company that never joined Vouch must
NOT come back "scam" just because we have no record of it. That would
be a false accusation. "Can't verify" is the honest answer there.
"""
from dataclasses import dataclass, field


@dataclass
class Signals:
    # domain-side signals
    domain_status: str | None = None       # official | lookalike_high | lookalike_medium | unrelated | None
    domain_imitates: str | None = None
    domain_age_days: int | None = None
    is_free_email: bool = False

    # registry / recruiter signals
    company_known: bool = False
    recruiter_registered: bool = False

    # email auth signals
    dmarc: str | None = None               # pass | fail | none | None
    dkim: str | None = None
    spf: str | None = None
    reply_to_mismatch: bool = False

    # offer document signals (only set when verifying a PDF/QR)
    offer_found: bool = False
    signature_valid: bool | None = None
    hash_matches: bool | None = None

    # free-text scam pattern flags
    text_flags: list[dict] = field(default_factory=list)


def decide(sig: Signals) -> dict:
    reasons: list[str] = []
    positive: list[str] = []
    hard_fail = False

    # --- offer/PDF verification path (strongest possible evidence) ---
    if sig.offer_found:
        if sig.signature_valid is False:
            return {
                "verdict": "scam",
                "reasons": ["The cryptographic signature on this record is invalid — "
                            "this offer was not issued the way it claims to have been."],
            }
        if sig.hash_matches is False:
            return {
                "verdict": "scam",
                "reasons": ["This document's content does not match what the company "
                            "originally signed — it appears to have been edited after issue."],
            }
        if sig.signature_valid and sig.hash_matches:
            return {
                "verdict": "verified",
                "reasons": ["Signature and document contents match exactly what the "
                            "company issued."],
            }

    # --- domain / email path ---
    if sig.domain_status in ("lookalike_high", "lookalike_medium"):
        hard_fail = True
        reasons.append(
            f"This domain imitates the real company domain "
            f"({sig.domain_imitates})."
        )

    if sig.domain_age_days is not None and sig.domain_age_days < 30:
        reasons.append(f"The sending domain was registered only "
                        f"{sig.domain_age_days} day(s) ago.")

    if sig.company_known and sig.dmarc == "fail":
        hard_fail = True
        reasons.append("This message fails DMARC for the domain it claims to be from "
                        "— it was not actually sent by that domain.")

    if sig.reply_to_mismatch:
        reasons.append("The reply-to address points somewhere different from the "
                        "visible sender address.")

    if sig.is_free_email:
        reasons.append("Sent from a free personal email provider rather than a "
                        "company domain.")

    if sig.company_known and not sig.recruiter_registered and sig.domain_status == "official":
        reasons.append("This sender is not in the company's list of authorized recruiters.")

    high_flags = [f for f in sig.text_flags if f["severity"] == "high"]
    other_flags = [f for f in sig.text_flags if f["severity"] != "high"]
    for f in sig.text_flags:
        reasons.append(f["label"])

    if len(high_flags) >= 2:
        hard_fail = True
    elif len(high_flags) == 1 and (reasons or sig.domain_status != "official"):
        hard_fail = True

    if hard_fail:
        return {"verdict": "scam", "reasons": reasons or ["Multiple scam indicators detected."]}

    if (
        sig.company_known
        and sig.domain_status == "official"
        and sig.dmarc != "fail"  # "pass", "none"/absent, or not checked (bare address) are all fine here --
        and sig.recruiter_registered  # an explicit "fail" is caught above as a hard_fail already
        and not high_flags
        and not other_flags
    ):
        if sig.dmarc == "pass":
            reason = ("Sent from the company's official domain by a registered "
                      "recruiter, and email authentication passed.")
        else:
            reason = ("This address belongs to a registered recruiter at a verified "
                      "company. (No email was checked, so this confirms the address "
                      "itself, not that a specific message came from it.)")
        return {"verdict": "verified", "reasons": [reason]}

    if not reasons:
        reasons = ["We don't have enough information to confirm or refute this. "
                   "Proceed carefully and verify independently with the company."]
    return {"verdict": "unverifiable", "reasons": reasons}


if __name__ == "__main__":
    # 1. verified offer PDF
    r = decide(Signals(offer_found=True, signature_valid=True, hash_matches=True))
    assert r["verdict"] == "verified", r

    # 2. tampered offer PDF
    r = decide(Signals(offer_found=True, signature_valid=True, hash_matches=False))
    assert r["verdict"] == "scam", r

    # 3. clean official recruiter email
    r = decide(Signals(
        domain_status="official", company_known=True, recruiter_registered=True,
        dmarc="pass",
    ))
    assert r["verdict"] == "verified", r

    # 3b. bare recruiter address, no email headers at all (dmarc stays None) --
    # this is the "Recruiter" tab's core use case and previously regressed to
    # "unverifiable" even for a genuinely registered recruiter
    r = decide(Signals(
        domain_status="official", company_known=True, recruiter_registered=True,
    ))
    assert r["verdict"] == "verified", r

    # 3c. same, but the address is NOT a registered recruiter -- must NOT verify
    r = decide(Signals(
        domain_status="official", company_known=True, recruiter_registered=False,
    ))
    assert r["verdict"] != "verified", r

    # 4. lookalike domain + scam text
    r = decide(Signals(
        domain_status="lookalike_medium", domain_imitates="northwind.xyz",
        domain_age_days=2,
        text_flags=[
            {"flag": "gift_cards", "severity": "high", "label": "Asks for payment via gift cards"},
            {"flag": "early_pii", "severity": "high", "label": "Requests sensitive info"},
        ],
    ))
    assert r["verdict"] == "scam", r

    # 5. unknown company, no red flags -> unverifiable, NOT scam
    r = decide(Signals())
    assert r["verdict"] == "unverifiable", r

    print("verdict self-test passed (all 5 cases)")
