"""
Domain trust signals: look-alike detection, permutation generation for
the monitor, DNS liveness, and RDAP domain age. Network calls (RDAP, DNS)
are wrapped so a flaky connection degrades to "unknown" instead of
crashing the request -- important on hackathon wifi.
"""
import re
from datetime import datetime, timezone

import dns.resolver
import requests
from rapidfuzz import fuzz

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
    "proton.me", "protonmail.com", "icloud.com", "aol.com",
}

# characters/substrings that make two domains *look* the same to a human
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "5": "s", "8": "b",
    "rn": "m", "vv": "w", "cl": "d",
}

FILLER_WORDS = ["careers", "jobs", "hiring", "recruit", "recruiting",
                "hr", "team", "official", "inc", "corp", "group"]


def normalize_domain_name(domain: str) -> str:
    """Strip TLD, apply homoglyph folding, remove filler words/hyphens."""
    name = domain.lower().split(".")[0]
    for k, v in HOMOGLYPHS.items():
        name = name.replace(k, v)
    name = name.replace("-", "").replace("_", "")
    for word in FILLER_WORDS:
        name = name.replace(word, "")
    return name


def classify_domain(candidate: str, official_domains: list[str]) -> dict:
    """
    Returns {"status": "official" | "lookalike_high" | "lookalike_medium"
             | "unrelated", "imitates": <official domain or None>}
    Official domains are checked first so the real domain can never be
    flagged as imitating itself.
    """
    candidate = candidate.lower().strip()
    if candidate in [d.lower() for d in official_domains]:
        return {"status": "official", "imitates": None}

    best_score, best_match, best_status = 0, None, "unrelated"
    cand_norm = normalize_domain_name(candidate)

    for official in official_domains:
        off_norm = normalize_domain_name(official)
        if cand_norm == off_norm:
            return {"status": "lookalike_high", "imitates": official}

        score = fuzz.ratio(cand_norm, off_norm)
        contains = off_norm in cand_norm and len(off_norm) >= 4
        if contains and score > best_score:
            best_score, best_match, best_status = score, official, "lookalike_medium"
        elif score >= 85 and score > best_score:
            best_score, best_match, best_status = score, official, "lookalike_medium"

    if best_status != "unrelated":
        return {"status": best_status, "imitates": best_match}
    return {"status": "unrelated", "imitates": None}


def generate_permutations(domain: str) -> list[str]:
    """
    Lightweight stand-in for dnstwist: generates common typosquat/
    impersonation variants of a domain without needing an external
    binary. Good enough to demo the monitor; swap for real dnstwist
    if it's installed and network access allows it.
    """
    name, _, tld = domain.partition(".")
    variants = set()

    # character substitution (adjacent-key typos, kept small & realistic)
    swaps = {"o": "0", "i": "1", "e": "3", "s": "5", "a": "@"}
    for i, ch in enumerate(name):
        if ch in swaps:
            variants.add(name[:i] + swaps[ch] + name[i + 1:] + "." + tld)

    # omission / duplication
    for i in range(len(name)):
        variants.add(name[:i] + name[i + 1:] + "." + tld)          # drop a char
        variants.add(name[:i] + name[i] + name[i:] + "." + tld)    # double a char

    # hyphenation + filler words
    for word in ["careers", "jobs", "hiring", "hr"]:
        variants.add(f"{name}-{word}.{tld}")
        variants.add(f"{word}-{name}.{tld}")

    # alternate TLDs
    for alt_tld in ["com", "co", "io", "net", "org", "xyz"]:
        if alt_tld != tld:
            variants.add(f"{name}.{alt_tld}")

    variants.discard(domain)
    return sorted(variants)


def check_txt_record(domain: str, expected_token: str, timeout: float = 6.0) -> bool:
    """
    Domain-ownership check for company signup: looks up the TXT record at
    _vouch.<domain> and confirms it contains the token we issued. Only
    someone who controls the domain's DNS can pass this -- the same
    technique Google Search Console / Microsoft 365 use.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(f"_vouch.{domain}", "TXT")
        for record in answers:
            # TXT records come back as quoted byte strings; join + strip quotes
            value = b"".join(record.strings).decode(errors="replace")
            if expected_token in value:
                return True
        return False
    except Exception:
        return False


def dns_liveness(domain: str) -> dict:
    """Cheap check: does this domain resolve, and can it receive mail?"""
    result = {"resolves": False, "has_mx": False}
    try:
        dns.resolver.resolve(domain, "A")
        result["resolves"] = True
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(domain, "MX")
        result["has_mx"] = len(list(answers)) > 0
    except Exception:
        pass
    return result


def domain_age_days(domain: str, timeout: float = 6.0) -> int | None:
    """
    RDAP lookup for registration date. Returns None (unknown) rather than
    raising on timeout/no-record -- callers should treat None as
    "couldn't determine," not as a red flag by itself.
    """
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=timeout)
        if resp.status_code != 200:
            return None
        data = resp.json()
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                created = datetime.fromisoformat(
                    event["eventDate"].replace("Z", "+00:00")
                )
                return (datetime.now(timezone.utc) - created).days
    except Exception:
        pass
    return None


def is_free_email_provider(domain: str | None) -> bool:
    if not domain:
        return False
    return domain.lower() in FREE_EMAIL_PROVIDERS


if __name__ == "__main__":
    official = ["northwind.xyz"]
    tests = {
        "northwind.xyz": "official",
        "n0rthwind.xyz": "lookalike_high",
        # exact brand match plus a filler word -> still an exact normalized
        # match, so this is high risk, not medium
        "northwind-careers.com": "lookalike_high",
        # close but not an exact normalized match -> medium (fuzzy match)
        "northwnd.xyz": "lookalike_medium",
        "totallyunrelated.com": "unrelated",
    }
    for domain, expected in tests.items():
        result = classify_domain(domain, official)
        status = result["status"]
        mark = "OK" if status == expected else "FAIL"
        print(f"[{mark}] {domain:28s} -> {status:16s} expected {expected}")
        assert status == expected, f"{domain}: got {status}, expected {expected}"

    perms = generate_permutations("northwind.xyz")
    print(f"\ngenerated {len(perms)} permutations, sample: {perms[:8]}")

    print("\ndomain_checks self-test passed")
