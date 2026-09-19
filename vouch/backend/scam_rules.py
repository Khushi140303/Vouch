"""
Keyword/regex rules for common job-scam patterns. These are the rules
that DECIDE which flags fire -- the LLM (see explain.py) only turns
already-decided flags into a plain-English sentence, so results stay
consistent, auditable, and can't be talked out of a verdict.

Patterns are drawn from FTC consumer alerts and r/Scams reports of real
job-offer scams. Replace/extend RULES with more examples you collect
before the hackathon.
"""
import re

# (flag_id, severity, human_label, regex)
RULES = [
    (
        "payment_request", "high",
        "Asks the candidate to pay a fee",
        r"(pay|payment|deposit|fee|purchase|reimburse)\w*.{0,40}"
        r"(onboard|training|equipment|background\s*check|starter\s*kit|processing)",
    ),
    (
        "check_scam", "high",
        "Describes a check/equipment scam pattern",
        r"(check|cheque|cashier'?s?\s*check).{0,60}"
        r"(equipment|vendor|supplies|deposit\s*(it|this)|cash\s*it)",
    ),
    (
        "gift_cards", "high",
        "Asks for payment via gift cards",
        r"gift\s*-?\s*cards?",
    ),
    (
        "early_pii", "high",
        "Requests sensitive personal/financial info before an offer",
        r"\b(ssn|social\s*security|bank\s*account|routing\s*number|"
        r"date\s*of\s*birth|passport\s*number)\b",
    ),
    (
        "offplatform_chat", "medium",
        "Pushes the conversation to an unofficial chat app",
        r"\b(telegram|whatsapp|signal\s*app|wire\s*app|wickr|google\s*hangouts)\b",
    ),
    (
        "urgency", "low",
        "Uses high-pressure urgency language",
        r"(within\s*\d+\s*(hours?|minutes?)|act\s*now|immediately|"
        r"urgent(ly)?|offer\s*(expires|will\s*be\s*withdrawn))",
    ),
    (
        "too_good", "low",
        "Unusually high pay for minimal effort/experience",
        r"(no\s*experience\s*(needed|required)).{0,40}"
        r"(\$\d{2,4}\s*/?\s*(hr|hour|day))|(\$\d{2,4}\s*/?\s*(hr|hour)).{0,40}"
        r"no\s*experience",
    ),
]


def scan_text(text: str) -> list[dict]:
    """Returns every rule that matched, most-severe implied by caller ordering."""
    hits = []
    lowered = text.lower()
    for flag_id, severity, label, pattern in RULES:
        if re.search(pattern, lowered, re.IGNORECASE):
            hits.append({"flag": flag_id, "severity": severity, "label": label})
    return hits


if __name__ == "__main__":
    scam_text = (
        "Congratulations on your new role! To begin onboarding, please pay a "
        "$150 equipment fee via gift cards within 24 hours. We'll also need "
        "your SSN and bank account to set up payroll. Our onboarding "
        "coordinator will continue this conversation on Telegram."
    )
    hits = scan_text(scam_text)
    flags = {h["flag"] for h in hits}
    assert "payment_request" in flags
    assert "gift_cards" in flags
    assert "early_pii" in flags
    assert "offplatform_chat" in flags
    assert "urgency" in flags
    print(f"scam_rules self-test passed, {len(hits)} flags fired:")
    for h in hits:
        print(f"  [{h['severity']:6s}] {h['label']}")

    clean_text = "Congratulations! Please find your official offer letter attached. Reply with any questions."
    assert scan_text(clean_text) == [], "clean text should not trigger any rule"
    print("clean-text negative test passed")
