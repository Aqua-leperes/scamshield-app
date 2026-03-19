"""
ai_model/detector.py  —  Combined Rule + ML detection engine
"""
import re
from ai_model.rules    import check_url, check_phone, check_text
from ai_model.ml_model import predict as ml_predict

RULE_WEIGHT = 0.45
ML_WEIGHT   = 0.55


def _verdict(score: float) -> str:
    if score >= 0.65: return "scam"
    if score >= 0.35: return "suspicious"
    return "safe"


def analyze(input_type: str, content: str, blacklists: dict = None) -> dict:
    """
    input_type: 'sms' | 'email' | 'url' | 'phone'
    Returns dict with risk_score, verdict, confidence, triggered_rules, etc.
    """
    bl = blacklists or {"urls": [], "phones": set(), "keywords": []}

    # 1. Rule-based
    if input_type == "url":
        rule_result = check_url(content, bl.get("urls", []))
    elif input_type == "phone":
        rule_result = check_phone(content, bl.get("phones", set()))
    else:
        rule_result = check_text(content, bl.get("keywords", []))
        for url in re.findall(r"https?://\S+", content):
            u = check_url(url, bl.get("urls", []))
            rule_result["score"] = min(rule_result["score"] + u["score"] * 0.3, 1.0)
            rule_result["rules"].extend([f"embedded_{r}" for r in u["rules"]])

    rule_score     = rule_result["score"]
    triggered_rules = list(set(rule_result["rules"]))

    # 2. ML model
    if input_type in ("sms", "email", "url"):
        ml_result = ml_predict(content)
        ml_score  = ml_result["ml_score"]
    else:
        ml_score = rule_score   # phones: rely on rules only

    # 3. Combine
    if rule_score >= 0.9:
        final_score = rule_score
    else:
        final_score = (RULE_WEIGHT * rule_score) + (ML_WEIGHT * ml_score)

    final_score = round(min(max(final_score, 0.0), 1.0), 4)
    verdict     = _verdict(final_score)

    dist = min(abs(final_score - 0.35), abs(final_score - 0.65))
    confidence = round(min(0.5 + dist, 1.0), 4)

    return {
        "risk_score":      final_score,
        "verdict":         verdict,
        "confidence":      confidence,
        "triggered_rules": triggered_rules,
        "ml_score":        round(ml_score, 4),
        "rule_score":      round(rule_score, 4),
    }