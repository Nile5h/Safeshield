from datetime import datetime, timezone
from pathlib import Path
import sys
from tempfile import NamedTemporaryFile
from uuid import uuid4
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict

from analyzer.apk_analyzer import analyze_apk
from analyzer.message_analyzer import analyze_message
from analyzer.url_analyzer import analyze_url
from risk_engine import evaluate_message_risk, message_hash
from database import analyses_collection


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

    try:
        if analyses_collection is not None:
            analyses_collection.insert_one(analysis_document)
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail="Analysis completed, but the result could not be saved.",
        ) from error

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
    }
    try:
        if analyses_collection is not None:
            analyses_collection.insert_one(analysis_document)
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail="Analysis completed, but the result could not be saved.",
        ) from error

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
        }
        try:
            if analyses_collection is not None:
                analyses_collection.insert_one(analysis_document)
        except Exception:
            pass

        return result
    finally:
        try:
            import os
            os.unlink(temp_path)
        except OSError:
            pass


@app.get("/history")
def get_history(limit: int = 100, scan_type: str | None = None) -> list[dict]:
    if analyses_collection is None:
        return []

    try:
        query = {}
        if scan_type:
            query["type"] = scan_type.lower()

        cursor = analyses_collection.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit)
        history = []
        for doc in cursor:
            ts = doc.get("timestamp")
            if isinstance(ts, datetime):
                doc["timestamp"] = ts.isoformat()

            # Security constraint: NEVER store or return message plaintext; SHA-256 hash only.
            if doc.get("type") == "message":
                doc.pop("message", None)
                msg_hash = doc.get("message_hash", "")
                doc["target"] = f"Hash: {msg_hash[:12]}..." if msg_hash else "Message Scan"
            elif doc.get("type") == "url":
                doc["target"] = doc.get("original_url", doc.get("normalized_url", "URL Scan"))
            elif doc.get("type") == "apk":
                doc["target"] = doc.get("app_name") or doc.get("filename") or doc.get("package_name") or "APK Scan"
            else:
                doc["target"] = "Unknown Scan"

            history.append(doc)
        return history
    except Exception as error:
        print(f"Error reading history from MongoDB: {error}")
        return []


@app.get("/reports/stats")
def get_reports_stats() -> dict:
    fallback_response = {
        "total_scans": 0,
        "verdicts": {"SAFE": 0, "FRAUD": 0, "SUSPICIOUS": 0},
        "risk_levels": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "by_type": {"message": 0, "url": 0, "apk": 0},
        "mongodb_connected": False,
    }

    if analyses_collection is None:
        return fallback_response

    try:
        docs = list(analyses_collection.find({}, {"_id": 0}))
        total_scans = len(docs)

        verdicts = {"SAFE": 0, "FRAUD": 0, "SUSPICIOUS": 0}
        risk_levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_type = {"message": 0, "url": 0, "apk": 0}

        for doc in docs:
            stype = doc.get("type", "message")
            if stype in by_type:
                by_type[stype] += 1

            rlevel = str(doc.get("risk_level", "LOW")).upper()
            if rlevel in risk_levels:
                risk_levels[rlevel] += 1
            else:
                risk_levels["LOW"] += 1

            verdict = doc.get("verdict")
            if verdict:
                v_upper = str(verdict).upper()
                if v_upper in ("SAFE", "LOW_RISK"):
                    verdicts["SAFE"] += 1
                elif v_upper in ("MALICIOUS", "DANGEROUS", "FRAUD"):
                    verdicts["FRAUD"] += 1
                elif v_upper in ("SUSPICIOUS", "MEDIUM"):
                    verdicts["SUSPICIOUS"] += 1
                else:
                    verdicts["SAFE"] += 1
            else:
                if rlevel in ("CRITICAL", "HIGH"):
                    verdicts["FRAUD"] += 1
                elif rlevel == "MEDIUM":
                    verdicts["SUSPICIOUS"] += 1
                else:
                    verdicts["SAFE"] += 1

        return {
            "total_scans": total_scans,
            "verdicts": verdicts,
            "risk_levels": risk_levels,
            "by_type": by_type,
            "mongodb_connected": True,
        }
    except Exception as error:
        print(f"Error calculating stats from MongoDB: {error}")
        return fallback_response


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
    )