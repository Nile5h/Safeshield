"""
image_analyzer.py – SafeShield Image Security Risk Analysis Pipeline.

Extracts text via OCR (Pytesseract) and decodes QR codes (OpenCV / Pyzbar),
then passes extracted artifacts through SafeShield's URL and Message Risk Analyzers.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

# Ensure backend directory is in sys.path for direct imports
BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


import cv2
import numpy as np
from PIL import Image, UnidentifiedImageError

try:
    import pyzbar.pyzbar as pyzbar
    _PYZBAR_AVAILABLE = True
except Exception:
    _PYZBAR_AVAILABLE = False

import pytesseract

from analyzer.message_analyzer import analyze_message
from analyzer.url_analyzer import analyze_url
from risk_engine import evaluate_message_risk

# URL extraction regex pattern
_URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s<>'\"`]+",
    re.IGNORECASE,
)


def _configure_tesseract() -> None:
    """Discover and configure the Tesseract OCR executable path if available."""
    if os.environ.get("TESSERACT_CMD"):
        pytesseract.pytesseract.tesseract_cmd = os.environ["TESSERACT_CMD"]
        return

    which_path = shutil.which("tesseract")
    if which_path:
        pytesseract.pytesseract.tesseract_cmd = which_path
        return

    candidate_paths = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expanduser(r"~\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"),
        "/usr/bin/tesseract",
        "/usr/local/bin/tesseract",
        "/opt/homebrew/bin/tesseract",
    ]
    for p in candidate_paths:
        if os.path.exists(p):
            pytesseract.pytesseract.tesseract_cmd = p
            break


_configure_tesseract()


def _decode_qr_codes(cv_img: np.ndarray, pil_img: Image.Image) -> list[str]:
    """Extract and decode all QR codes present in the image."""
    decoded_strings: list[str] = []

    # 1. OpenCV QRCodeDetector (Multi-detection)
    try:
        detector = cv2.QRCodeDetector()
        retval, decoded_info, points, _ = detector.detectAndDecodeMulti(cv_img)
        if retval and decoded_info:
            for item in decoded_info:
                if item and item.strip():
                    decoded_strings.append(item.strip())
        elif not decoded_strings:
            # Fallback to single decode
            val, _, _ = detector.detectAndDecode(cv_img)
            if val and val.strip():
                decoded_strings.append(val.strip())
    except Exception:
        pass

    # 2. If nothing found, try on preprocessed grayscale / thresholded image
    if not decoded_strings:
        try:
            gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
            # Try contrast stretched / otsu threshold
            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
            detector = cv2.QRCodeDetector()
            retval, decoded_info, _, _ = detector.detectAndDecodeMulti(thresh)
            if retval and decoded_info:
                for item in decoded_info:
                    if item and item.strip():
                        decoded_strings.append(item.strip())
        except Exception:
            pass

    # 3. Try Pyzbar if available
    if _PYZBAR_AVAILABLE:
        try:
            pyzbar_results = pyzbar.decode(pil_img)
            for res in pyzbar_results:
                if res.data:
                    val = res.data.decode("utf-8", errors="ignore").strip()
                    if val and val not in decoded_strings:
                        decoded_strings.append(val)
        except Exception:
            pass

    # Deduplicate while preserving order
    return list(dict.fromkeys(decoded_strings))


def _extract_text_ocr(pil_img: Image.Image) -> tuple[str, str]:
    """
    Extract text from image using Pytesseract.
    Returns (extracted_text, ocr_status).
    """
    try:
        text = pytesseract.image_to_string(pil_img)
        cleaned = text.strip()
        if cleaned:
            return cleaned, "success"
        return "", "no_text_found"
    except pytesseract.TesseractNotFoundError:
        return "", "tesseract_not_installed"
    except Exception as exc:
        return "", f"ocr_error: {str(exc)}"


def _extract_urls_from_text(text: str) -> list[str]:
    """Find all URLs embedded in a text string."""
    if not text:
        return []
    matches = _URL_REGEX.findall(text)
    cleaned_urls: list[str] = []
    for m in matches:
        # Strip trailing punctuation often captured by regex in natural language sentences
        url = re.sub(r"[.,;:!?)\]}>]+$", "", m.strip())
        if url and url not in cleaned_urls:
            cleaned_urls.append(url)
    return cleaned_urls


def _risk_level_from_score(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def analyze_image(image_bytes: bytes) -> dict[str, Any]:
    """
    Analyzes an uploaded image for security threats:
      1. Decodes QR codes to discover embedded URLs/links.
      2. Performs OCR to extract screenshot / SMS / poster text.
      3. Passes extracted URLs to `analyze_url`.
      4. Passes extracted text to `analyze_message` and `evaluate_message_risk`.
      5. Synthesizes a unified risk score, risk level, verdict, reasons, and recommendation.
    """
    if not image_bytes:
        raise ValueError("Image bytes cannot be empty.")

    # 1. Load image with PIL and OpenCV
    try:
        pil_img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except (UnidentifiedImageError, Exception) as exc:
        raise ValueError(f"Invalid image format: {exc}")

    # Convert to OpenCV BGR
    cv_img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

    # 2. Decode QR Codes
    qr_codes = _decode_qr_codes(cv_img, pil_img)
    qr_status = "success" if qr_codes else "no_qr_found"

    # 3. Perform OCR Text Extraction
    extracted_text, ocr_status = _extract_text_ocr(pil_img)

    # 4. Extract all URLs from QR codes and OCR text
    extracted_urls: list[str] = []

    # Check QR codes for URLs or text with URLs
    for qr_val in qr_codes:
        if re.match(r"^(?:https?://|www\.|ftp://)", qr_val, re.IGNORECASE):
            if qr_val not in extracted_urls:
                extracted_urls.append(qr_val)
        else:
            # Check if QR code contains a URL inside natural text
            sub_urls = _extract_urls_from_text(qr_val)
            for u in sub_urls:
                if u not in extracted_urls:
                    extracted_urls.append(u)

    # Check OCR text for URLs
    ocr_urls = _extract_urls_from_text(extracted_text)
    for u in ocr_urls:
        if u not in extracted_urls:
            extracted_urls.append(u)

    # 5. Run URL Analysis on extracted URLs
    url_analyses: list[dict[str, Any]] = []
    for raw_url in extracted_urls:
        url_to_test = raw_url
        if url_to_test.lower().startswith("www."):
            url_to_test = f"http://{url_to_test}"
        try:
            analysis_obj = analyze_url(url_to_test)
            url_analyses.append({
                "original_url": raw_url,
                "normalized_url": analysis_obj.normalized_url,
                "risk_score": analysis_obj.risk_score,
                "risk_level": analysis_obj.risk_level,
                "category": analysis_obj.category,
                "verdict": analysis_obj.verdict,
                "confidence": analysis_obj.confidence,
                "reasons": analysis_obj.reasons,
                "detected_indicators": analysis_obj.detected_indicators,
                "recommendation": analysis_obj.recommendation,
                "model_prediction": analysis_obj.model_prediction,
                "model_confidence": analysis_obj.model_confidence,
                "rule_confidence": analysis_obj.rule_confidence,
                "domain_valid": analysis_obj.domain_valid,
                "live_inspection": analysis_obj.live_inspection,
            })
        except Exception as exc:
            url_analyses.append({
                "original_url": raw_url,
                "normalized_url": raw_url,
                "risk_score": 50,
                "risk_level": "HIGH",
                "category": "suspicious_url",
                "verdict": "FRAUD",
                "confidence": 50,
                "reasons": [f"URL analysis error: {str(exc)}"],
                "detected_indicators": ["url_analysis_failed"],
                "recommendation": "Do not visit this URL.",
                "model_prediction": "unavailable",
                "model_confidence": 0,
                "rule_confidence": 0,
                "domain_valid": False,
                "live_inspection": {},
            })

    # 6. Run Message / Text Analysis on OCR text (or non-URL QR text)
    message_analysis: dict[str, Any] | None = None
    text_to_analyze = extracted_text.strip()
    
    # If no OCR text but QR code had non-URL text, analyze that text
    if not text_to_analyze and qr_codes:
        non_url_qr = [q for q in qr_codes if not q.lower().startswith(("http://", "https://", "www."))]
        if non_url_qr:
            text_to_analyze = "\n".join(non_url_qr)

    if text_to_analyze and any(c.isalnum() for c in text_to_analyze):
        try:
            indicators = analyze_message(text_to_analyze)
            msg_risk = evaluate_message_risk(indicators, text_to_analyze)
            message_analysis = {
                "risk_score": msg_risk.risk_score,
                "risk_level": msg_risk.risk_level,
                "category": msg_risk.category,
                "confidence": msg_risk.confidence,
                "confidence_level": msg_risk.confidence_level,
                "reasons": msg_risk.reasons,
                "detected_indicators": msg_risk.detected_indicators,
                "recommendation": msg_risk.recommendation,
                "model_prediction": msg_risk.model_prediction,
                "model_confidence": msg_risk.model_confidence,
                "rule_confidence": msg_risk.rule_confidence,
            }
        except Exception as exc:
            message_analysis = {
                "risk_score": 0,
                "risk_level": "LOW",
                "category": "Benign",
                "confidence": 50,
                "confidence_level": "LOW",
                "reasons": [f"Text evaluation note: {str(exc)}"],
                "detected_indicators": [],
                "recommendation": "No conclusive text threat detected.",
                "model_prediction": "unavailable",
                "model_confidence": 0,
                "rule_confidence": 0,
            }

    # 7. Synthesize Unified Risk Metrics
    url_scores = [u["risk_score"] for u in url_analyses]
    max_url_score = max(url_scores) if url_scores else 0
    msg_score = message_analysis["risk_score"] if message_analysis else 0

    if url_analyses and message_analysis:
        combined_score = max(max_url_score, msg_score)
        # Compound risk bonus if both components independently detect elevated risk
        if max_url_score >= 25 and msg_score >= 25:
            combined_score = min(100, combined_score + 10)
    elif url_analyses:
        combined_score = max_url_score
    elif message_analysis:
        combined_score = msg_score
    else:
        combined_score = 0

    risk_level = _risk_level_from_score(combined_score)

    # Determine Verdict
    any_fraud_url = any(u.get("verdict") == "FRAUD" for u in url_analyses)
    msg_critical_high = (
        message_analysis is not None
        and message_analysis.get("risk_level") in ("CRITICAL", "HIGH")
    )
    if combined_score >= 50 or any_fraud_url or msg_critical_high:
        verdict = "FRAUD"
    elif combined_score >= 25 or any(u.get("verdict") == "SUSPICIOUS" for u in url_analyses) or (
        message_analysis and message_analysis.get("risk_level") == "MEDIUM"
    ):
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    # Category classification
    category = "benign"
    if any_fraud_url or max_url_score >= 50:
        fraud_url = next((u for u in url_analyses if u.get("risk_score", 0) >= 50), None)
        url_cat = fraud_url.get("category") if fraud_url else None
        category = url_cat if (url_cat and url_cat != "benign") else "qr_phishing"
    elif msg_critical_high:
        category = message_analysis.get("category", "scam") if message_analysis else "scam"
    elif qr_codes and not extracted_urls:
        category = "qr_code"
    elif extracted_text and not combined_score >= 25:
        category = "benign_document"
    elif combined_score >= 25:
        category = "suspicious"

    # Aggregate Reasons
    reasons: list[str] = []
    if qr_codes:
        reasons.append(f"Decoded {len(qr_codes)} QR code(s) from image.")
    for u in url_analyses:
        if u.get("reasons"):
            for r in u["reasons"]:
                reasons.append(f"[URL: {u.get('normalized_url') or u.get('original_url')}] {r}")
    if message_analysis and message_analysis.get("reasons"):
        for r in message_analysis["reasons"]:
            reasons.append(f"[Text] {r}")

    if not reasons:
        if not qr_codes and not extracted_text:
            reasons.append("No QR codes or textual indicators found in the image.")
        else:
            reasons.append("No suspicious or malicious indicators detected in the image.")

    reasons = list(dict.fromkeys(reasons))

    # Aggregate Detected Indicators
    indicators: list[str] = []
    if qr_codes:
        indicators.append("qr_code_detected")
    if extracted_urls:
        indicators.append("url_detected")
    if extracted_text:
        indicators.append("ocr_text_extracted")

    for u in url_analyses:
        indicators.extend(u.get("detected_indicators", []))
    if message_analysis:
        indicators.extend(message_analysis.get("detected_indicators", []))

    indicators = list(dict.fromkeys(indicators))

    # Determine Consolidated Recommendation
    if verdict == "FRAUD":
        recommendation = (
            "High risk detected. Do not open extracted links, scan QR codes, or follow instructions from this image. "
            "Verify any requests independently through an official source."
        )
    elif verdict == "SUSPICIOUS":
        recommendation = (
            "Potential risk detected. Review extracted text and links carefully before proceeding. "
            "Do not enter personal credentials or send payments."
        )
    else:
        recommendation = (
            "No immediate cyber threats detected. Verify the sender or context before acting on any instructions."
        )

    # Compute overall confidence
    confidences = []
    for u in url_analyses:
        confidences.append(u.get("confidence", 75))
    if message_analysis:
        confidences.append(message_analysis.get("confidence", 75))
    confidence = round(sum(confidences) / len(confidences)) if confidences else 85

    return {
        "risk_score": combined_score,
        "risk_level": risk_level,
        "category": category,
        "verdict": verdict,
        "confidence": confidence,
        "reasons": reasons,
        "detected_indicators": indicators,
        "recommendation": recommendation,
        "extracted_text": extracted_text,
        "qr_codes": qr_codes,
        "extracted_urls": extracted_urls,
        "message_analysis": message_analysis,
        "url_analyses": url_analyses,
        "ocr_status": ocr_status,
        "qr_status": qr_status,
    }
