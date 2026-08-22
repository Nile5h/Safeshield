from datetime import datetime, timezone
from pathlib import Path
import sys
from tempfile import NamedTemporaryFile
from uuid import uuid4

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import FastAPI, File, HTTPException, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict

from analyzer.apk_analyzer import analyze_apk
from analyzer.image_analyzer import analyze_image
from analyzer.message_analyzer import analyze_message
from analyzer.url_analyzer import analyze_url
from risk_engine import evaluate_message_risk, message_hash
from database import (
    analyses_collection,
    save_analysis,
    get_all_analyses,
    get_aggregated_stats,
)


# cool
class MessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="User-selected message content to review.",
    )


class MessageAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
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


class URLRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., min_length=1, max_length=2048)


class URLAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    original_url: str
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
    live_inspection: dict = Field(default_factory=dict)


class ImageAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    filename: str
    risk_score: int
    risk_level: str
    category: str
    verdict: str
    confidence: int
    reasons: list[str]
    detected_indicators: list[str]
    recommendation: str
    extracted_text: str
    qr_codes: list[str]
    extracted_urls: list[str]
    message_analysis: dict | None = None
    url_analyses: list[dict] = Field(default_factory=list)
    ocr_status: str
    qr_status: str



# ── Authentication models & demo credentials ──────────────────────────────────
class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=100)


class LoginResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_token: str
    token_type: str = "bearer"
    username: str
    role: str = "analyst"
    message: str = "Authentication successful"


# Hardcoded demo users (username -> password)
_DEMO_USERS: dict[str, str] = {
    "admin":   "password123",
    "analyst": "safeshield2026",
    "demo":    "demo123",
}


app = FastAPI(
    title="SafeShield Backend",
    version="1.0.0",
    description="User-initiated, explainable message risk analysis for SafeShield.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://safeshield-frontend.onrender.com",  # Your frontend Render URL
    ],
    allow_origin_regex=r"^chrome-extension://.*$",
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/")
def root() -> dict[str, str]:
    return {
        "service": "SafeShield Backend",
        "status": "ok",
        "health_url": "/health",
        "docs_url": "/docs",
    }


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "SafeShield Backend",
        "version": "1.0.0",
    }


@app.post("/login", response_model=LoginResponse)
def login_endpoint(payload: LoginRequest, response: Response) -> LoginResponse:
    username = payload.username.strip()
    password = payload.password.strip()

    expected = _DEMO_USERS.get(username)
    if not expected or expected != password:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password.",
        )

    import secrets
    token = f"ss_token_{secrets.token_hex(16)}"

    # ── CYBER-9: Set compliant HttpOnly + Secure + SameSite session cookie ──
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,       # Prevents XSS-based cookie theft
        secure=True,         # Cookie transmitted over HTTPS only
        samesite="lax",      # Mitigates CSRF; allows top-level GET navigations
        max_age=3600,        # 1-hour expiry
    )

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        username=username,
        role="admin" if username == "admin" else "analyst",
        message="Authentication successful",
    )


@app.post("/analyze/message", response_model=MessageAnalysisResponse)
def analyze_message_endpoint(
    payload: MessageRequest,
) -> MessageAnalysisResponse:

    if not payload.message or not payload.message.strip():
        raise HTTPException(
            status_code=400,
            detail="Message cannot be empty.",
        )

    if len(payload.message.strip()) > 5000:
        raise HTTPException(
            status_code=413,
            detail="Message is too long for analysis.",
        )

    indicator_matches = analyze_message(payload.message)

    analysis = evaluate_message_risk(indicator_matches, payload.message)

    analysis_id = f"SS-{uuid4().hex[:10].upper()}"

    analysis_document = {
        "analysis_id": analysis_id,
        "type": "message",
        "message_hash": message_hash(payload.message),
        "timestamp": datetime.now(timezone.utc),
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "category": analysis.category,
        "confidence": analysis.confidence,
        "reasons": analysis.reasons,
        "detected_indicators": analysis.detected_indicators,
        "recommendation": analysis.recommendation,
        "model_prediction": analysis.model_prediction,
    }

    save_analysis(analysis_document)

    return MessageAnalysisResponse(
        analysis_id=analysis_id,
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        category=analysis.category,
        confidence=analysis.confidence,
        confidence_level=analysis.confidence_level,
        reasons=analysis.reasons,
        detected_indicators=analysis.detected_indicators,
        recommendation=analysis.recommendation,
        model_prediction=analysis.model_prediction,
        model_confidence=analysis.model_confidence,
        rule_confidence=analysis.rule_confidence,
    )


@app.post("/analyze/url", response_model=URLAnalysisResponse)
def analyze_url_endpoint(payload: URLRequest) -> URLAnalysisResponse:
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    analysis = analyze_url(url)
    analysis_id = f"SS-{uuid4().hex[:10].upper()}"
    analysis_document = {
        "analysis_id": analysis_id,
        "type": "url",
        "original_url": url,
        "normalized_url": analysis.normalized_url,
        "timestamp": datetime.now(timezone.utc),
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "category": analysis.category,
        "verdict": analysis.verdict,
        "confidence": analysis.confidence,
        "reasons": analysis.reasons,
        "detected_indicators": analysis.detected_indicators,
        "recommendation": analysis.recommendation,
        "model_prediction": analysis.model_prediction,
        "live_inspection": analysis.live_inspection,
    }

    save_analysis(analysis_document)

    return URLAnalysisResponse(
        analysis_id=analysis_id,
        original_url=url,
        normalized_url=analysis.normalized_url,
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        category=analysis.category,
        verdict=analysis.verdict,
        confidence=analysis.confidence,
        reasons=analysis.reasons,
        detected_indicators=analysis.detected_indicators,
        recommendation=analysis.recommendation,
        model_prediction=analysis.model_prediction,
        model_confidence=analysis.model_confidence,
        rule_confidence=analysis.rule_confidence,
        domain_valid=analysis.domain_valid,
        live_inspection=analysis.live_inspection or {},
    )


ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}
ALLOWED_IMAGE_MIME_TYPES = {"image/jpeg", "image/png", "image/webp", "image/bmp"}


@app.post("/analyze/image", response_model=ImageAnalysisResponse)
async def analyze_image_endpoint(file: UploadFile = File(...)) -> ImageAnalysisResponse:
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Filename is missing.",
        )

    file_ext = Path(file.filename).suffix.lower()
    content_type = (file.content_type or "").lower()

    if file_ext not in ALLOWED_IMAGE_EXTENSIONS and content_type not in ALLOWED_IMAGE_MIME_TYPES:
        raise HTTPException(
            status_code=400,
            detail="Invalid image format. Supported formats: JPEG, PNG, WEBP, BMP.",
        )

    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(
            status_code=400,
            detail="Uploaded image file is empty.",
        )

    try:
        result = analyze_image(image_bytes)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Image analysis failed: {str(exc)}",
        )

    analysis_id = f"SS-{uuid4().hex[:10].upper()}"

    analysis_document = {
        "analysis_id": analysis_id,
        "type": "image",
        "filename": file.filename,
        "timestamp": datetime.now(timezone.utc),
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "category": result["category"],
        "verdict": result["verdict"],
        "confidence": result["confidence"],
        "reasons": result["reasons"],
        "detected_indicators": result["detected_indicators"],
        "recommendation": result["recommendation"],
        "extracted_text": result["extracted_text"],
        "qr_codes": result["qr_codes"],
        "extracted_urls": result["extracted_urls"],
        "ocr_status": result["ocr_status"],
        "qr_status": result["qr_status"],
    }

    save_analysis(analysis_document)

    return ImageAnalysisResponse(
        analysis_id=analysis_id,
        filename=file.filename,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        category=result["category"],
        verdict=result["verdict"],
        confidence=result["confidence"],
        reasons=result["reasons"],
        detected_indicators=result["detected_indicators"],
        recommendation=result["recommendation"],
        extracted_text=result["extracted_text"],
        qr_codes=result["qr_codes"],
        extracted_urls=result["extracted_urls"],
        message_analysis=result["message_analysis"],
        url_analyses=result["url_analyses"],
        ocr_status=result["ocr_status"],
        qr_status=result["qr_status"],
    )


@app.post("/analyze/apk")
async def analyze_apk_endpoint(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a valid APK file.",
        )

    with NamedTemporaryFile(suffix=".apk", delete=False) as temp_file:
        temp_file.write(await file.read())
        temp_path = temp_file.name

    try:
        result = analyze_apk(temp_path)
        if not result.get("success"):
            raise HTTPException(
                status_code=400,
                detail=result.get("error", "APK analysis failed."),
            )

        result["filename"] = file.filename
        result["file_name"] = file.filename
        if "component_counts" not in result:
            result["component_counts"] = {
                "activities": result.get("activities_count", 0),
                "services": result.get("services_count", 0),
                "receivers": result.get("receivers_count", 0),
                "providers": result.get("providers_count", 0),
            }
        if "suspicious_apis" not in result and "api_findings" in result:
            result["suspicious_apis"] = result["api_findings"]

        analysis_id = f"SS-{uuid4().hex[:10].upper()}"
        verdict = result.get("verdict", "low_risk")
        risk_level = "CRITICAL" if verdict == "dangerous" else ("HIGH" if verdict == "suspicious" else "LOW")
        result["analysis_id"] = analysis_id
        result["risk_level"] = risk_level

        analysis_document = {
            "analysis_id": analysis_id,
            "type": "apk",
            "filename": file.filename,
            "app_name": result.get("app_name"),
            "package_name": result.get("package_name"),
            "sha256": result.get("sha256"),
            "timestamp": datetime.now(timezone.utc),
            "risk_score": result.get("risk_score", 0),
            "risk_level": risk_level,
            "verdict": verdict,
            "permission_count": result.get("permission_count", 0),
            # ---- Advanced static analysis fields ----
            "suspicious_permissions": result.get("suspicious_permissions", []),
            "suspicious_apis": result.get("suspicious_apis", []),
            "manifest_issues": result.get("manifest_issues", []),
            "dangerous_combos": result.get("dangerous_combos", []),
            "network_indicators": result.get("network_indicators", {}),
            "certificate_info": result.get("certificate_info", {}),
        }
        save_analysis(analysis_document)

        return result
    finally:
        try:
            import os
            os.unlink(temp_path)
        except OSError:
            pass


@app.get("/history")
def get_history(limit: int = 100, scan_type: str | None = None) -> list[dict]:
    return get_all_analyses(scan_type=scan_type, limit=limit)


@app.get("/reports/stats")
def get_reports_stats() -> dict:
    return get_aggregated_stats()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
    )