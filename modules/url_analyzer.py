import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".icu", ".vip", ".club", ".online", ".site"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "rb.gy", "cutt.ly"}
PHISHING_KEYWORDS = {
    "login", "verify", "update", "secure", "account", "banking", "kyc", "sbi",
    "hdfc", "icici", "paytm", "phonepe", "gpay", "free", "claim", "gift", "bonus",
    "reward", "suspend", "blocked", "alert", "confirm", "wallet", "password", "otp"
}

def extract_urls(text: str) -> list:
    if not text:
        return []
    pattern = r'(https?://[^\s<>"]+|www\.[^\s<>"]+)'
    return re.findall(pattern, text, flags=re.IGNORECASE)

def extract_url(text: str) -> str:
    urls = extract_urls(text)
    return urls[0] if urls else ""

def analyze_url(url: str) -> dict:
    if not url:
        return {"score": 0.0, "domain": "", "reasons": []}

    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0]
    full_lower = url.lower()

    score = 0.0
    reasons = []

    # 1. Unencrypted HTTP check
    if parsed.scheme == "http":
        score += 30.0
        reasons.append("Unencrypted HTTP link (No SSL)")

    # 2. Raw IP Address URL check (e.g., http://192.168.1.45/...)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        score += 45.0
        reasons.append("Raw IP address used instead of domain name")

    # 3. URL Shortener check
    if domain in URL_SHORTENERS:
        score += 35.0
        reasons.append(f"Obfuscated URL shortener ({domain})")

    # 4. Suspicious Top-Level Domain (TLD)
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 30.0
            reasons.append(f"High-risk TLD ({tld})")
            break

    # 5. Phishing / Banking / Lure keywords in URL path or domain
    matched_kw = [kw for kw in PHISHING_KEYWORDS if kw in full_lower]
    if matched_kw:
        kw_score = min(40.0, len(matched_kw) * 15.0)
        score += kw_score
        reasons.append(f"Suspicious URL keywords ({', '.join(matched_kw[:3])})")

    # 6. Excessive subdomains or '@' symbol trick
    if "@" in url:
        score += 40.0
        reasons.append("URL contains '@' credential masking symbol")
    if domain.count(".") >= 3 and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        score += 20.0
        reasons.append("Multiple suspicious subdomains")

    final_score = min(100.0, round(score, 2))
    return {
        "score": final_score,
        "domain": domain,
        "reasons": reasons
    }

def analyze_urls_in_text(text: str, extra_urls: list = None) -> dict:
    urls = extract_urls(text)
    if extra_urls:
        urls.extend(extra_urls)

    seen = set()
    unique_urls = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    if not unique_urls:
        return {"score": 0.0, "urls": [], "domains": [], "reasons": []}

    max_score = 0.0
    all_reasons = []
    domains = []

    for u in unique_urls:
        res = analyze_url(u)
        if res["domain"]:
            domains.append(res["domain"])
        if res["score"] > max_score:
            max_score = res["score"]
        for r in res["reasons"]:
            if r not in all_reasons:
                all_reasons.append(r)

    return {
        "score": max_score,
        "urls": unique_urls,
        "domains": list(dict.fromkeys(domains)),
        "reasons": all_reasons
    }