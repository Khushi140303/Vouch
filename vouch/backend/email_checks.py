"""
Parses a raw email (the "Show original" / "View source" export from
Gmail/Outlook) and pulls out the signals that matter for scam
detection: SPF/DKIM/DMARC results the receiving mail server already
computed, and whether the visible From address lines up with where
replies would actually go.

We read the `Authentication-Results` header the *receiving* mailbox
provider (Gmail, Outlook, etc.) attaches, rather than re-implementing
DKIM crypto verification ourselves -- that header is exactly what a
real inbox already trusts, and it is present on effectively every
message delivered to a modern mailbox.
"""
import email
import email.message
import re
from email.utils import parseaddr


def _extract_domain(address: str) -> str | None:
    addr = parseaddr(address)[1]
    if "@" not in addr:
        return None
    return addr.split("@")[-1].lower()


def _parse_auth_results(header_value: str) -> dict:
    """
    Authentication-Results headers look like:
      mx.google.com;
         dkim=pass header.d=northwind.xyz;
         spf=pass smtp.mailfrom=northwind.xyz;
         dmarc=pass header.from=northwind.xyz
    We only need pass/fail/none per mechanism.
    """
    results = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{mechanism}=(\w+)", header_value, re.IGNORECASE)
        results[mechanism] = match.group(1).lower() if match else "none"
    return results


def get_body_text(msg: email.message.Message) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    return part.get_payload(decode=True).decode(errors="replace")
                except Exception:
                    continue
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                try:
                    raw = part.get_payload(decode=True).decode(errors="replace")
                    return re.sub("<[^>]+>", " ", raw)
                except Exception:
                    continue
        return ""
    try:
        return msg.get_payload(decode=True).decode(errors="replace")
    except Exception:
        return msg.get_payload() or ""


def analyze_raw_email(raw_email: str) -> dict:
    msg = email.message_from_string(raw_email)

    from_domain = _extract_domain(msg.get("From", ""))
    reply_to = parseaddr(msg.get("Reply-To", ""))[1]
    reply_to_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else None

    auth_header = msg.get("Authentication-Results", "")
    auth = _parse_auth_results(auth_header) if auth_header else {
        "spf": "none", "dkim": "none", "dmarc": "none",
    }

    from_address = parseaddr(msg.get("From", ""))[1].lower() or None

    return {
        "from_display": msg.get("From", ""),
        "from_address": from_address,
        "from_domain": from_domain,
        "reply_to": reply_to or None,
        "reply_to_domain": reply_to_domain,
        "reply_to_mismatch": bool(
            reply_to_domain and from_domain and reply_to_domain != from_domain
        ),
        "spf": auth["spf"],
        "dkim": auth["dkim"],
        "dmarc": auth["dmarc"],
        "auth_header_present": bool(auth_header),
        "subject": msg.get("Subject", ""),
        "body": get_body_text(msg),
    }


if __name__ == "__main__":
    sample = """From: "Northwind Recruiting" <hr@northwind.xyz>
Reply-To: hr.northwind@gmail.com
Subject: Your offer letter
Authentication-Results: mx.google.com;
   dkim=pass header.d=northwind.xyz;
   spf=pass smtp.mailfrom=northwind.xyz;
   dmarc=pass header.from=northwind.xyz
Content-Type: text/plain

Congratulations! To proceed, please send your SSN and a $200 deposit
for onboarding equipment via gift card.
"""
    result = analyze_raw_email(sample)
    assert result["from_domain"] == "northwind.xyz"
    assert result["reply_to_mismatch"] is True, "should catch reply-to going to gmail"
    assert result["dmarc"] == "pass"
    assert "SSN" in result["body"] or "ssn" in result["body"].lower()
    print("email_checks self-test passed")
    print(result)
