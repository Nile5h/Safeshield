from dataclasses import dataclass
from hashlib import sha256
from functools import lru_cache
from pathlib import Path

import joblib

from analyzer.message_analyzer import IndicatorMatch


MODEL_FILE = Path(__file__).resolve().parent / "ml" / "models" / "message_model.joblib"


@dataclass(frozen=True)
class MessageRiskAnalysis:
    risk_score: int
    risk_level: str
    category: str
    confidence: int
    confidence_level: str
    reasons: list[str]
    detected_indicators: list[str]
    recommendation: str
    model_prediction: str
    model_confidence: int
    rule_confidence: int


def _risk_level_from_score(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _generate_recommendation(score: int, reasons: list[str]) -> str:
    if score <= 24:
        return "No major suspicious indicators detected."

    if any("Download or install instruction detected." in reason for reason in reasons):
        return "Potentially suspicious. Do not click the link, do not install the file, and verify the sender through a trusted channel."

    if any("Credential, OTP, or account access request detected." in reason for reason in reasons):
        return "Potentially suspicious. Do not share passwords, OTP codes, or account details. Confirm the request through an official channel."

    return "Potentially suspicious. Avoid interacting with the message and verify the request through a trusted, independent source."


@lru_cache(maxsize=1)
def _load_model():
    if not MODEL_FILE.exists():
        return None
    try:
        return joblib.load(MODEL_FILE)
    except Exception:
        return None


def _category(text: str, names: set[str], suspicious: bool) -> str:
    normalized = text.lower()
    if not suspicious:
        return "Benign"
    if "download" in names and ("financial" in names or "banking" in names):
        return "malicious_download"
    if any(term in normalized for term in ("prize", "lottery", "you won", "congratulations")):
        return "scam"
    if "credential_request" in names:
        return "credential_theft"
    if "sensitive_request" in names and "financial" in names and "banking" in names:
        return "financial_fraud"
    if "sensitive_request" in names:
        return "credential_theft"
    if "threat" in names and ("banking" in names or "link" in names):
        return "phishing"
    if "financial" in names and "link" in names:
        return "financial_fraud"
    if "financial" in names and "urgent_language" in names:
        return "scam"
    if "financial" in names:
        return "financial_fraud"
    if "link" in names or "threat" in names:
        return "phishing"
    return "suspicious"


def evaluate_message_risk(indicators: list[IndicatorMatch], message: str) -> MessageRiskAnalysis:
    names = {indicator.name for indicator in indicators}
    reasons = list(dict.fromkeys(indicator.reason for indicator in indicators))
    model = _load_model()
    model_confidence = 0
    model_prediction = "unavailable"
    if model is not None:
        try:
            model_prediction = str(model.predict([message])[0])
            if hasattr(model, "predict_proba"):
                model_confidence = round(float(max(model.predict_proba([message])[0])) * 100)
        except Exception:
            model_prediction = "unavailable"

    strong_rule_count = sum(name in names for name in {"credential_request", "sensitive_request", "download", "threat"})
    combination_count = sum(
        pair.issubset(names)
        for pair in ({"urgent_language", "link"}, {"banking", "link"}, {"financial", "link"}, {"threat", "banking"})
    )
    rule_confidence = min(100, 35 + strong_rule_count * 20 + combination_count * 15)
    rule_suspicious = strong_rule_count > 0 or combination_count > 0 or len(names - {"banking"}) >= 2
    ml_suspicious = model_prediction == "suspicious"
    suspicious = rule_suspicious or ml_suspicious

    score = sum(indicator.points for indicator in indicators)
    if combination_count:
        score += 10
    if ml_suspicious and model_confidence >= 70:
        score += 10
    score = min(score, 100)
    if not suspicious:
        score = min(score, 24)

    risk_level = _risk_level_from_score(score)
    category = _category(message, names, suspicious)
    confidence = round((rule_confidence + model_confidence) / 2) if model_prediction != "unavailable" else rule_confidence
    confidence_level = "HIGH" if confidence >= 75 else "MEDIUM" if confidence >= 45 else "LOW"
    if not reasons and suspicious:
        reasons.append("Message pattern is inconsistent with ordinary conversation.")
    return MessageRiskAnalysis(
        risk_score=score,
        risk_level=risk_level,
        category=category,
        confidence=confidence,
        confidence_level=confidence_level,
        reasons=reasons,
        detected_indicators=sorted(names),
        recommendation=_generate_recommendation(score, reasons),
        model_prediction=model_prediction,
        model_confidence=model_confidence,
        rule_confidence=rule_confidence,
    )


def message_hash(message: str) -> str:
    return sha256(message.strip().encode("utf-8")).hexdigest()
