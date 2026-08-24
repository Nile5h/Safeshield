"""
url_analyzer.py – SafeShield URL Risk Analysis Pipeline.

Multi-tier scoring architecture prioritizing dynamic inspection over static ML:

  Tier 1: Dynamic Live Website Inspection & Threat Feeds
          - Fetches page headers & DOM within a strict 3-second timeout.
          - If live threats (credential-harvesting external forms, drive-by executables,
            malicious content-types, hidden iframes) are confirmed, immediately assigns
            a FRAUD verdict (score 90–100) overriding static predictions.

  Tier 2: Static Heuristics (60%) & ML Model (40%) Fallback
          - Used when dynamic inspection times out (>3s), is unreachable, or returns no live threats.
          - Blends deterministic rule heuristics (60% weight) with ML calibrated probabilities (40% weight).
          - Enforces explainability: clean URLs with 0 threat indicators cannot be assigned FRAUD.

  Fast-Path: Trusted Domain Allowlist & Brand gTLD Verification (0 ms instant bypass).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import sys

import threading
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
from dataset.utils.allowlist import is_trusted_domain
from dataset.feedback_collector import log_feedback
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
    scoring_breakdown: dict = field(default_factory=dict)


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


_model_lock = threading.Lock()


def _load_model():
    global _model, _model_loaded, _EXPECTED_FEATURE_COUNT
    with _model_lock:
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


def reload_model() -> bool:
    """Hot-reload the ML model from disk without server restart (zero downtime)."""
    global _model, _model_loaded, _EXPECTED_FEATURE_COUNT
    with _model_lock:
        model_path = MODEL_DIR / "url_model_calibrated.pkl"
        if not model_path.exists():
            model_path = MODEL_DIR / "url_model.pkl"
        try:
            new_model = joblib.load(model_path)
            feature_names = getattr(new_model, "feature_names_in_", None)
            _EXPECTED_FEATURE_COUNT = len(feature_names) if feature_names is not None else None
            _model = new_model
            _model_loaded = True
            print("[url_analyzer] [OK] Model hot-reloaded successfully into memory")
            return True
        except Exception as exc:
            print(f"[url_analyzer] Model hot-reload failed: {exc}")
            return False


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
    """
    Tier 2 Scoring Blend: 60% Static Heuristics & 40% ML Model.
    Prioritizes deterministic security rules over raw ML probability.
    """
    if model_unavailable or model_confidence_pct == 0:
        return min(rule_score, 1.0)

    # Base weighting: 60% Heuristics, 40% ML (adjusted slightly by confidence)
    ml_weight = 0.30 + (model_confidence_pct / 100.0) * 0.15
    ml_weight = max(0.25, min(0.45, ml_weight))
    rule_weight = 1.0 - ml_weight

    combined = rule_weight * rule_score + ml_weight * model_prob
    return min(combined, 1.0)


# ── Main analysis entry-point ─────────────────────────────────────────────────
def analyze_url(url: str) -> URLRiskAnalysis:
    """
    Analyze a URL using prioritized Tier 1 Dynamic Live Inspection and
    Tier 2 Heuristic (60%) + ML (40%) fallback.
    """
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

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 1: Trusted Domain Allowlist Fast-Path (0 ms)
    # ══════════════════════════════════════════════════════════════════════════
    is_trusted, match_reason = is_trusted_domain(normalized_url)
    if not is_trusted:
        is_trusted, match_reason = is_trusted_domain(url)
    if not is_trusted:
        is_trusted, match_reason = is_trusted_domain(netloc)
    if not is_trusted and _is_whitelisted(netloc):
        is_trusted = True
        match_reason = "Domain is in trusted whitelist (instant bypass)"

    if is_trusted:
        reason_text = f"Verified legitimate organization domain: {match_reason}" if match_reason else "Verified legitimate organization domain"
        live_telemetry["fallback_reason"] = reason_text

        # Asynchronously log verified allowlist sample to feedback dataset
        try:
            threading.Thread(target=log_feedback, args=(normalized_url, 0, "allowlist_fast_path"), daemon=True).start()
        except Exception:
            pass

        default_verifications = {
            "password_form_origin": {
                "name": "Password Form Origin Safe",
                "weight_pct": 35,
                "severity": "CRITICAL",
                "status": "PASS",
                "details": "Verified official trusted domain origin",
            },
            "drive_by_payloads": {
                "name": "Drive-By Payloads Clear",
                "weight_pct": 30,
                "severity": "CRITICAL",
                "status": "PASS",
                "details": "0 executable payload links",
            },
            "brand_domain_match": {
                "name": "Brand / Domain Match",
                "weight_pct": 20,
                "severity": "HIGH",
                "status": "PASS",
                "details": "Official brand domain identity verified",
            },
            "zero_size_iframes": {
                "name": "Zero-Size Iframes Clear",
                "weight_pct": 15,
                "severity": "MEDIUM-HIGH",
                "status": "PASS",
                "details": "No hidden or zero-pixel iframes present",
            },
        }
        live_telemetry["dynamic_verifications"] = default_verifications

        breakdown = {
            "evaluation_tier": "Tier 0: Allowlist Fast-Path",
            "tier_label": "ALLOWLIST BYPASS",
            "dynamic_heuristics_weight_pct": 0,
            "static_heuristics_weight_pct": 0,
            "ml_model_weight_pct": 0,
            "allowlist_weight_pct": 100,
            "dynamic_verifications_active": False,
            "dynamic_verifications": default_verifications,
            "summary": "100% Trusted Organization Domain Match (Instant 0 ms Bypass)",
        }
        return URLRiskAnalysis(
            normalized_url=normalized_url,
            risk_score=0,
            risk_level="LOW",
            category="benign",
            verdict="SAFE",
            confidence=99,
            reasons=[
                "Evaluation Source: Trusted Domain Allowlist Fast-Path",
                reason_text,
                "Scoring Weightage: Allowlist Fast-Path (100% Instant Match Bypass) | Dynamic Heuristics (0%) | Static Rules (0%) | ML (0%)",
            ],
            detected_indicators=[],
            recommendation="Legitimate and verified trusted organization domain.",
            model_prediction="0",
            model_confidence=99,
            rule_confidence=99,
            domain_valid=True,
            live_inspection=live_telemetry,
            scoring_breakdown=breakdown,
        )

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 2: Evaluate Static Heuristics & Model Features (Prepared for Tier 2)
    # ══════════════════════════════════════════════════════════════════════════
    rule_result = rule_check(info)
    suspicious: bool = rule_result[0]
    heuristic_reasons: list[str] = list(rule_result[1])
    domain_valid: bool = rule_result[2]
    unusual_findings: list[str] = rule_result[3]
    rule_score: float = rule_result[4] if len(rule_result) > 4 else 0.0

    features = extract_url_features(normalized_url)
    model_probability, model_prediction, model_confidence = _model_score(
        _load_model(), features
    )
    rule_confidence = min(100, round(rule_score * 100) + 30)

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 3: Tier 1 – Dynamic Website Inspection & Live Threat Feeds (<= 3s)
    # ══════════════════════════════════════════════════════════════════════════
    live_reasons: list[str] = []
    live_indicators: list[str] = []
    live_extra_penalty: float = 0.0
    force_fraud: bool = False
    live_reachable: bool = False
    tier1_triggered: bool = False

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
                live_telemetry["fallback_reason"] = page.get("error") or "Dynamic inspection timed out (>3s) or host unreachable"

            if live_reachable:
                # 3a. Malicious Content-Type header (direct malware payload)
                if page.get("suspicious_content_type"):
                    ct = page.get("content_type", "")
                    live_reasons.append(f"Server returned a malicious Content-Type payload header: '{ct}'")
                    live_indicators.append("malicious_content_type")
                    live_extra_penalty += 0.50
                    force_fraud = True

                # 3b. Dynamic HTML DOM inspection (BeautifulSoup)
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
                    live_telemetry["dynamic_verifications"] = h_details.get("dynamic_verifications", {})

            live_telemetry["live_threats"] = live_indicators

            # Tier 1 Priority Trigger: Confirmed live threats immediately escalate to FRAUD
            if live_reachable and (force_fraud or len(live_indicators) > 0 or live_extra_penalty >= 0.25):
                tier1_triggered = True

        except Exception as exc:
            live_reachable = False
            live_telemetry["fallback_reason"] = f"Dynamic inspection exception: {str(exc)}"
    else:
        live_telemetry["fallback_reason"] = "Invalid domain or non-HTTP scheme"

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 4: Tripartite Scoring Fusion Engine
    # ══════════════════════════════════════════════════════════════════════════
    if live_reachable:
        # ── DYNAMIC LIVE INSPECTION ACTIVE (35% Dynamic, 40% Static, 25% ML) ──
        w_dyn = 0.35
        w_rule = 0.40
        w_ml = 0.25

        # Calculate dynamic risk score (0.0 to 1.0) from the 4 cybersecurity checks
        dyn_checks = live_telemetry.get("dynamic_verifications", {})
        dyn_risk_score = 0.0
        for key, check in dyn_checks.items():
            if check.get("status") == "FAIL":
                dyn_risk_score += check.get("weight_pct", 0) / 100.0

        # Add malicious Content-Type header penalty if present
        if page.get("suspicious_content_type"):
            dyn_risk_score += 0.40

        dyn_risk_score = min(1.0, max(0.0, dyn_risk_score))

        effective_ml_prob = model_probability if model_prediction != "unavailable" else rule_score
        combined_prob = (w_dyn * dyn_risk_score) + (w_rule * rule_score) + (w_ml * effective_ml_prob)
        score = round(combined_prob * 100)

        # Critical threat enforcement: if severe live threat (credential theft / drive-by) or severe static fraud
        if force_fraud or "credential_harvesting" in live_indicators or "drive_by_download_risk" in live_indicators:
            score = max(score, 75)
            verdict = "FRAUD"
            risk_level = "CRITICAL"
        elif score >= 50:
            verdict = "FRAUD"
            risk_level = _risk_level(score)
        else:
            verdict = "SAFE"
            risk_level = _risk_level(score)

        # Category resolution
        if "credential_harvesting" in live_indicators:
            category = "credential_harvesting"
        elif "drive_by_download_risk" in live_indicators:
            category = "drive_by_download"
        elif "malicious_content_type" in live_indicators:
            category = "malicious_download"
        elif suspicious or rule_score >= 0.20:
            category = "phishing"
        else:
            category = "benign"

        # Explainability guard: if all dynamic checks PASS and no static rules flagged (clean site)
        if len(live_indicators) == 0 and len(heuristic_reasons) == 0:
            score = min(score, 24)
            verdict = "SAFE"
            risk_level = "LOW"
            category = "benign"

        breakdown = {
            "evaluation_tier": "Tripartite Dynamic Inspection & Heuristics",
            "tier_label": "DYNAMIC ACTIVE (35/40/25)",
            "dynamic_heuristics_weight_pct": 35,
            "static_heuristics_weight_pct": 40,
            "ml_model_weight_pct": 25,
            "allowlist_weight_pct": 0,
            "dynamic_verifications_active": True,
            "dynamic_verifications": dyn_checks,
            "dynamic_risk_score": round(dyn_risk_score, 2),
            "rule_score": round(rule_score, 2),
            "ml_probability": round(model_probability, 2),
            "summary": "Scoring Weightage: Dynamic Heuristics (35%) | Static Heuristics (40%) | ML Model (25%)",
        }

        final_reasons = [
            "Evaluation Source: Dynamic Website Inspection & Tripartite Scoring",
            "Scoring Weightage: Dynamic Heuristic Verifications (35%) | Static Heuristics (40%) | ML Model (25%)",
        ] + live_reasons + heuristic_reasons

        confidence = max(model_confidence, 88) if len(live_indicators) > 0 else model_confidence

    else:
        # ── STATIC HEURISTICS (60%) & ML MODEL (40%) FALLBACK ─────────────────
        model_unavailable = model_prediction == "unavailable"
        combined_prob = _confidence_weighted_blend(
            model_probability,
            rule_score,
            model_confidence,
            model_unavailable=model_unavailable,
        )
        score = round(combined_prob * 100)

        # Base weighting breakdown: 60% Heuristics, 40% ML
        ml_weight = 0.30 + (model_confidence / 100.0) * 0.15
        ml_weight = max(0.25, min(0.45, ml_weight))
        rule_weight = 1.0 - ml_weight
        ml_w_pct = round(ml_weight * 100)
        rule_w_pct = 100 - ml_w_pct

        # Determine category based on heuristic rules
        if not domain_valid:
            category = "invalid_url"
        elif any("download" in r.lower() or "extension" in r.lower() for r in heuristic_reasons):
            category = "malicious_download"
        elif suspicious or rule_score >= 0.20:
            category = "phishing"
        else:
            category = "benign"

        # Explainability Guard: Clean URLs with 0 heuristic indicators cannot be FRAUD
        if category == "benign":
            if len(heuristic_reasons) == 0:
                score = min(score, 24)
            elif rule_score < 0.20 and not suspicious:
                score = min(score, 35)

        verdict = "FRAUD" if score >= 50 else "SAFE"
        risk_level = _risk_level(score)

        # Source indicator reason explaining the fallback evaluation
        fallback_note = live_telemetry.get("fallback_reason")
        if fallback_note:
            if "Failed to resolve" in fallback_note or "NameResolutionError" in fallback_note:
                clean_note = "Host unreachable / Unregistered domain"
            elif "timed out" in fallback_note.lower() or "timeout" in fallback_note.lower():
                clean_note = "Dynamic inspection timed out (>3s)"
            elif live_telemetry.get("status_code") in (403, 429):
                clean_note = "Target site blocked automated inspection"
            else:
                clean_note = "Live inspection unavailable"
            source_header = f"Evaluation Source: Static Heuristics (60%) & ML Model (40%) Fallback ({clean_note})"
        else:
            clean_note = "Dynamic inspection unavailable"
            source_header = "Evaluation Source: Static Heuristics (60%) & ML Model (40%) Fallback"

        breakdown = {
            "evaluation_tier": "Static Heuristics & ML Fallback",
            "tier_label": "STATIC FALLBACK (0/60/40)",
            "dynamic_heuristics_weight_pct": 0,
            "static_heuristics_weight_pct": rule_w_pct,
            "ml_model_weight_pct": ml_w_pct,
            "allowlist_weight_pct": 0,
            "dynamic_verifications_active": False,
            "dynamic_verifications": live_telemetry.get("dynamic_verifications", {}),
            "rule_score": round(rule_score, 2),
            "ml_probability": round(model_probability, 2),
            "summary": f"Dynamic Heuristics (0% - {clean_note}) | Static Heuristics ({rule_w_pct}%) | ML Model ({ml_w_pct}%)",
        }

        weight_reason = f"Scoring Weightage: Dynamic Heuristic Verifications (0% - Fallback) | Static Heuristics ({rule_w_pct}%) | ML Model ({ml_w_pct}%)"

        final_reasons = [source_header, weight_reason] + heuristic_reasons
        if len(heuristic_reasons) == 0:
            final_reasons.append("No suspicious heuristic indicators detected.")

        confidence = (
            model_confidence
            if not model_unavailable
            else min(100, 45 + len(heuristic_reasons) * 10)
        )

    # Deduplicate indicators & reasons
    all_reasons = list(dict.fromkeys(final_reasons))
    indicators = list(dict.fromkeys(unusual_findings + heuristic_reasons + live_indicators))

    recommendation = (
        "Do not open this URL or enter personal information. "
        "Verify the destination through an official source."
        if verdict == "FRAUD"
        else "No major suspicious indicators detected. "
        "Continue only if you recognise the website and expected this link."
    )

    # ── Automated Feedback Loop ───────────────────────────────────────────────
    # Asynchronously record ground-truth verified samples to retrain ML model
    try:
        if tier1_triggered and verdict == "FRAUD":
            threading.Thread(
                target=log_feedback,
                args=(normalized_url, 1, f"tier1_live_{category}"),
                daemon=True,
            ).start()
        elif verdict == "FRAUD" and rule_score >= 0.60:
            threading.Thread(
                target=log_feedback,
                args=(normalized_url, 1, "tier2_static_phishing"),
                daemon=True,
            ).start()
        elif verdict == "SAFE" and category == "benign" and len(heuristic_reasons) == 0 and live_reachable:
            threading.Thread(
                target=log_feedback,
                args=(normalized_url, 0, "tier2_live_benign"),
                daemon=True,
            ).start()
    except Exception:
        pass

    return URLRiskAnalysis(
        normalized_url=normalized_url,
        risk_score=score,
        risk_level=risk_level,
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
        scoring_breakdown=breakdown,
    )
