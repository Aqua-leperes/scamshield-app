"""
ai_model/rules.py  —  Rule-based scam detection
"""
import re
from urllib.parse import urlparse

SUSPICIOUS_URL_PATTERNS = [
    r"bit\.ly", r"tinyurl\.com", r"t\.co", r"goo\.gl",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"(paypal|amazon|google|microsoft|apple|mpesa|safaricom|kcb|equity)[^.]*\.(xyz|top|tk|ml|ga|cf|ru|cn)",
    r"login.*verify", r"verify.*login",
    r"account.*suspend", r"suspend.*account",
]

SUSPICIOUS_PHONE_PATTERNS = [
    r"^\+1900", r"^\+44909", r"^\+255", r"^0900", r"^\+[0-9]{12,}",
]

SCAM_PHRASES = [
    "you have won", "claim your prize", "send your pin", "send your otp",
    "do not share your pin", "congratulations you have been selected",
    "your account will be deactivated", "free money", "nigerian prince",
    "inheritance transfer", "western union", "wire transfer now",
    "bitcoin wallet", "click here to claim", "mpesa pin",
    "safaricom account suspended", "kcb account blocked",
    "equity verification code", "send your mpesa pin", "verify immediately",
]


def check_url(url: str, blacklist_urls: list = None) -> dict:
    score = 0.0
    rules = []
    url_lower = url.lower()
    if blacklist_urls:
        for entry in blacklist_urls:
            if entry.get("url") in url or entry.get("domain", "") in url:
                return {"score": 1.0, "rules": ["blacklisted_url"]}
    for pattern in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, url_lower):
            score += 0.25
            rules.append(f"url_pattern:{pattern[:25]}")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        score += 0.15
        rules.append("no_https")
    hostname = parsed.hostname or ""
    if hostname.count(".") > 3:
        score += 0.2
        rules.append("excessive_subdomains")
    return {"score": min(score, 1.0), "rules": rules}


def check_phone(phone: str, blacklist_phones: set = None) -> dict:
    score = 0.0
    rules = []
    phone_clean = re.sub(r"[\s\-()]", "", phone)
    if blacklist_phones and phone_clean in blacklist_phones:
        return {"score": 1.0, "rules": ["blacklisted_phone"]}
    for pattern in SUSPICIOUS_PHONE_PATTERNS:
        if re.match(pattern, phone_clean):
            score += 0.5
            rules.append("suspicious_phone_prefix")
            break
    return {"score": min(score, 1.0), "rules": rules}


def check_text(text: str, keyword_list: list = None) -> dict:
    score = 0.0
    rules = []
    text_lower = text.lower()
    for phrase in SCAM_PHRASES:
        if phrase in text_lower:
            score += 0.35
            rules.append(f"phrase:{phrase[:40]}")
    if keyword_list:
        for kw in keyword_list:
            if kw["keyword"].lower() in text_lower:
                score += float(kw["weight"]) * 0.2
                rules.append(f"keyword:{kw['keyword']}")
    urgency_count = len(re.findall(
        r"\b(urgent|immediately|now|hurry|expire|suspend|block|verify)\b", text_lower
    ))
    if urgency_count >= 2:
        score += 0.2
        rules.append(f"urgency_words:{urgency_count}")
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    if caps_ratio > 0.4 and len(text) > 20:
        score += 0.15
        rules.append("excessive_caps")
    embedded = re.findall(r"https?://\S+", text)
    for link in embedded:
        lr = check_url(link)
        score += lr["score"] * 0.4
        rules.extend([f"embedded_{r}" for r in lr["rules"]])
    return {"score": min(score, 1.0), "rules": list(set(rules))}