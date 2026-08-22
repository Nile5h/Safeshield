"""
url_analyzer.py – SafeShield URL risk analysis pipeline.

7-step pipeline (all steps preserve the URLRiskAnalysis schema / FastAPI contract):

  1. Whitelist fast-path              (instant — 0 ms)
  2. Static rule heuristics           (url_rules.rule_check)
  3. ML model scoring                 (url_model_calibrated.pkl)
  4. Static score fusion              (confidence-weighted blend)
  5. Live page fetch                  (live_inspector.fetch_page  ≤ 3 s wall-clock)
  6. HTML heuristics on live body     (url_rules.inspect_html_content with BeautifulSoup)
  7. Live score fusion + FRAUD gate   (additive penalty, force_fraud override)

The URLRiskAnalysis dataclass preserves all original fields and adds live_inspection
telemetry so the frontend UI can display real-time inspection statistics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import sys

import joblib
import pandas as pd

# ── Path setup ─────────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

PROJECT_DIR = Path(__file__).resolve().parents[2]
URL_CHECKER_DIR = PROJECT_DIR / "url_checker"
MODEL_DIR = URL_CHECKER_DIR / "model"
if str(URL_CHECKER_DIR) not in sys.path:
    sys.path.insert(0, str(URL_CHECKER_DIR))

from dataset.utils.url_features import extract_url_features
from dataset.utils.url_normalize import normalize_url
from dataset.utils.url_rules import rule_check, inspect_html_content
from analyzer.live_inspector import fetch_page

_EXPECTED_FEATURE_COUNT: int | None = None


# ── Return schema (FastAPI contract preserved) ────────────────────────────────
@dataclass(frozen=True)
class URLRiskAnalysis:
    normalized_url: str
    risk_score: int
    risk_level: str
    category: str
    verdict: str
    confidence: int
    reasons: list[str]
    detected_indicators: list[str]
    recommendation: str
    model_prediction: str
    model_confidence: int
    rule_confidence: int
    domain_valid: bool
    live_inspection: dict = field(default_factory=dict)


# ── ML model (lazy singleton) ─────────────────────────────────────────────────
_model = None
_model_loaded = False


def _is_whitelisted(netloc: str) -> bool:
    whitelist_file = URL_CHECKER_DIR / "dataset" / "forced_negatives.txt"
    if not whitelist_file.exists():
        return False
    try:
        with open(whitelist_file, "r", encoding="utf-8") as f:
            trusted = {line.strip().lower() for line in f if line.strip()}
        domain = netloc.lower().split(":")[0]
        return domain in trusted or any(domain.endswith("." + t) for t in trusted)
    except Exception:
        return False


def _load_model():
    global _model, _model_loaded, _EXPECTED_FEATURE_COUNT
    if _model_loaded:
        return _model
    _model_loaded = True
    model_path = MODEL_DIR / "url_model_calibrated.pkl"
    if not model_path.exists():
        model_path = MODEL_DIR / "url_model.pkl"
    try:
        _model = joblib.load(model_path)
        feature_names = getattr(_model, "feature_names_in_", None)
        if feature_names is not None:
            _EXPECTED_FEATURE_COUNT = len(feature_names)
    except Exception:
        _model = None
    return _model


def _risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _align_features(features: list, model) -> list:
    """Pad or trim the feature vector to match what the model was trained on."""
    feature_names = getattr(model, "feature_names_in_", None)
    if feature_names is None:
        return features
    expected = len(feature_names)
    current = len(features)
    if current == expected:
        return features
    if current < expected:
        return features + [0.0] * (expected - current)
    return features[:expected]


def _model_score(model, features: list) -> tuple[float, str, int]:
    """Run the ML model; return (fraud_probability, prediction_label, confidence_pct)."""
    if model is None:
        return 0.0, "unavailable", 0
    try:
        aligned = _align_features(features, model)
        feature_names = getattr(model, "feature_names_in_", None)
        model_input = (
            pd.DataFrame([aligned], columns=feature_names)
            if feature_names is not None
            else [aligned]
        )
        probabilities = model.predict_proba(model_input)[0]
        classes = list(getattr(model, "classes_", range(len(probabilities))))
        fraud_index = next(
            (
                idx
                for idx, label in enumerate(classes)
                if str(label).lower() in {"1", "true", "fraud", "phishing", "malicious"}
            ),
            len(probabilities) - 1,
        )
        fraud_probability = float(probabilities[fraud_index])
        prediction = str(model.predict(model_input)[0])
        confidence = round(max(float(v) for v in probabilities) * 100)
        return fraud_probability, prediction, confidence
    except Exception:
        return 0.0, "unavailable", 0


def _confidence_weighted_blend(
    model_prob: float,
    rule_score: float,
    model_confidence_pct: int,
    model_unavailable: bool = False,
) -> float:
    """Blend ML probability (60% weight) and rule score (40% weight) smoothly."""
    if model_unavailable or model_confidence_pct == 0:
        return min(rule_score, 1.0)

    ml_weight = 0.50 + (model_confidence_pct / 100.0) * 0.30
    ml_weight = max(0.50, min(0.80, ml_weight))
    rule_weight = 1.0 - ml_weight
    combined = ml_weight * model_prob + rule_weight * rule_score
    return min(combined, 1.0)


# ── Main analysis entry-point ─────────────────────────────────────────────────
def analyze_url(url: str) -> URLRiskAnalysis:
    """Analyze a URL for risk using a 7-step static + live inspection pipeline."""
    info = normalize_url(url)
    normalized_url = info.get("normalized_url", "")
    netloc = info.get("netloc", "")
    scheme = info.get("scheme", "")

    # Telemetry data collected during live inspection
    live_telemetry: dict = {
        "attempted": False,
        "reachable": False,
        "status_code": None,
        "content_type": "",
        "server": "",
        "response_time_ms": 0,
        "page_title": "",
        "forms_count": 0,
        "password_inputs_count": 0,
        "iframes_count": 0,
        "hidden_iframes_count": 0,
        "links_checked_count": 0,
        "executable_links_count": 0,
        "live_threats": [],
        "fallback_reason": None,
    }

    # ── Step 1: Whitelist fast-path ────────────────────────────────────────────
    if _is_whitelisted(netloc):
        live_telemetry["fallback_reason"] = "Domain is in trusted whitelist (instant bypass)"
        return URLRiskAnalysis(
            normalized_url=normalized_url,
            risk_score=0,
            risk_level="LOW",
            category="benign",
            verdict="SAFE",
            confidence=99,
            reasons=[],
            detected_indicators=[],
            recommendation="Legitimate and trusted domain.",
            model_prediction="0",
            model_confidence=99,
            rule_confidence=99,
            domain_valid=True,
            live_inspection=live_telemetry,
        )

    # ── Step 2: Static rule heuristics ────────────────────────────────────────
    rule_result = rule_check(info)
    suspicious: bool = rule_result[0]
    reasons: list[str] = list(rule_result[1])
    domain_valid: bool = rule_result[2]
    unusual_findings: list[str] = rule_result[3]
    rule_score: float = rule_result[4] if len(rule_result) > 4 else 0.0

    # ── Step 3: ML model scoring ───────────────────────────────────────────────
    features = extract_url_features(normalized_url)
    model_probability, model_prediction, model_confidence = _model_score(
        _load_model(), features
    )

    # ── Step 4: Static score fusion ────────────────────────────────────────────
    model_unavailable = model_prediction == "unavailable"
    combined_probability = _confidence_weighted_blend(
        model_probability, rule_score, model_confidence,
        model_unavailable=model_unavailable,
    )
    score = round(combined_probability * 100)

    if model_unavailable and not suspicious:
        score = min(score, 24)

    # ── Step 5: Live page fetch (≤ 3 s) ───────────────────────────────────────
    live_reasons: list[str] = []
    live_indicators: list[str] = []
    live_extra_penalty: float = 0.0
    force_fraud: bool = False
    live_reachable: bool = False

    # Only attempt the live fetch when the domain is syntactically valid and
    # the scheme is http or https (skip data:, ftp:, javascript:, etc.)
    if domain_valid and scheme in ("http", "https"):
        live_telemetry["attempted"] = True
        try:
            page = fetch_page(normalized_url)
            live_reachable = page.get("reachable", False)
            live_telemetry["reachable"] = live_reachable
            live_telemetry["status_code"] = page.get("status_code")
            live_telemetry["content_type"] = page.get("content_type", "")
            live_telemetry["server"] = page.get("server", "")
            live_telemetry["response_time_ms"] = page.get("response_time_ms", 0)

            if not live_reachable:
                live_telemetry["fallback_reason"] = page.get("error") or "Host unreachable or request timed out"

            if live_reachable:
                # 5a. Malicious Content-Type header (payload served directly)
                if page.get("suspicious_content_type"):
                    ct = page.get("content_type", "")
                    live_reasons.append(
                        f"Server returned a malicious Content-Type: '{ct}'"
                    )
                    live_indicators.append("malicious_content_type")
                    live_extra_penalty += 0.45
                    force_fraud = True

                # 5b. HTML heuristics — BeautifulSoup parsing
                html_body = page.get("html", "")
                if html_body:
                    h_reasons, h_indicators, h_penalty, h_force, h_details = inspect_html_content(
                        html_body, info, return_details=True
                    )
                    live_reasons.extend(h_reasons)
                    live_indicators.extend(h_indicators)
                    live_extra_penalty += h_penalty
                    if h_force:
                        force_fraud = True

                    live_telemetry["page_title"] = h_details.get("title", "")
                    live_telemetry["forms_count"] = h_details.get("forms_count", 0)
                    live_telemetry["password_inputs_count"] = h_details.get("password_inputs_count", 0)
                    live_telemetry["iframes_count"] = h_details.get("iframes_count", 0)
                    live_telemetry["hidden_iframes_count"] = h_details.get("hidden_iframes_count", 0)
                    live_telemetry["links_checked_count"] = h_details.get("links_checked_count", 0)
                    live_telemetry["executable_links_count"] = h_details.get("executable_links_count", 0)

            live_telemetry["live_threats"] = live_indicators

        except Exception as exc:
            live_reachable = False
            live_telemetry["fallback_reason"] = str(exc)
    else:
        live_telemetry["fallback_reason"] = "Invalid domain or unsupported scheme"

    # ── Step 6: Fuse live findings into score ──────────────────────────────────
    if live_reachable and live_extra_penalty > 0:
        live_score_boost = round(live_extra_penalty * 60)
        score = min(score + live_score_boost, 100)

    # Force CRITICAL threshold (≥ 75) for confirmed credential theft or drive-by
    if force_fraud:
        score = max(score, 75)

    # ── Step 7: Build the final result ────────────────────────────────────────
    all_reasons = list(dict.fromkeys(reasons + live_reasons))
    indicators = list(dict.fromkeys(unusual_findings + reasons + live_indicators))

    if not domain_valid:
        category = "invalid_url"
    elif "credential_harvesting" in live_indicators:
        category = "credential_harvesting"
    elif "drive_by_download_risk" in live_indicators:
        category = "drive_by_download"
    elif "malicious_content_type" in live_indicators:
        category = "malicious_download"
    elif any("download" in r.lower() or "extension" in r.lower() for r in reasons):
        category = "malicious_download"
    elif suspicious or (live_reachable and len(live_reasons) > 0):
        category = "phishing"
    else:
        category = "benign"

    verdict = "FRAUD" if (score >= 50 or force_fraud) else "SAFE"

    confidence = (
        model_confidence
        if model_prediction != "unavailable"
        else min(100, 45 + len(all_reasons) * 10)
    )

    recommendation = (
        "Do not open this URL or enter personal information. "
        "Verify the destination through an official source."
        if verdict == "FRAUD"
        else "No major suspicious indicators detected. "
        "Continue only if you recognise the website and expected this link."
    )

    rule_confidence = min(100, round(rule_score * 100) + 30)

    return URLRiskAnalysis(
        normalized_url=normalized_url,
        risk_score=score,
        risk_level=_risk_level(score),
        category=category,
        verdict=verdict,
        confidence=confidence,
        reasons=all_reasons,
        detected_indicators=indicators,
        recommendation=recommendation,
        model_prediction=model_prediction,
        model_confidence=model_confidence,
        rule_confidence=rule_confidence,
        domain_valid=domain_valid,
        live_inspection=live_telemetry,
    )
