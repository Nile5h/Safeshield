import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from dotenv import load_dotenv
from pymongo import MongoClient

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "safeshield")

LOCAL_DATA_DIR = BASE_DIR / "data"
LOCAL_DATA_DIR.mkdir(exist_ok=True)
LOCAL_STORAGE_FILE = LOCAL_DATA_DIR / "analyses_history.json"
_file_lock = Lock()

client = None
analyses_collection = None

if MONGODB_URI:
    try:
        client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        db = client[MONGODB_DATABASE]
        analyses_collection = db["analyses"]
    except Exception as exc:
        print(f"MongoDB initialization warning: {exc}")
        client = None
        analyses_collection = None


def test_database_connection() -> bool:
    if client is None:
        return False
    try:
        client.admin.command("ping")
        return True
    except Exception as error:
        print(f"MongoDB connection failed: {error}")
        return False


def _serialize_doc(doc: dict) -> dict:
    clean = dict(doc)
    ts = clean.get("timestamp")
    if isinstance(ts, datetime):
        clean["timestamp"] = ts.isoformat()
    clean.pop("_id", None)
    return clean


def save_analysis(doc: dict) -> bool:
    """Save analysis document to MongoDB if configured, otherwise fallback to local JSON file."""
    # 1. MongoDB if configured
    if analyses_collection is not None:
        try:
            analyses_collection.insert_one(dict(doc))
            return True
        except Exception as error:
            print(f"MongoDB save failed, falling back to local storage: {error}")

    # 2. Local JSON file fallback
    with _file_lock:
        try:
            records = []
            if LOCAL_STORAGE_FILE.exists():
                try:
                    with open(LOCAL_STORAGE_FILE, "r", encoding="utf-8") as f:
                        records = json.load(f)
                except Exception:
                    records = []

            serialized = _serialize_doc(doc)
            records.insert(0, serialized)  # newest first
            records = records[:500]  # cap at 500 records

            with open(LOCAL_STORAGE_FILE, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2, ensure_ascii=False)
            return True
        except Exception as error:
            print(f"Local storage save failed: {error}")
            return False


def get_all_analyses(scan_type: str | None = None, limit: int = 100) -> list[dict]:
    """Retrieve scan history from MongoDB or local JSON storage."""
    raw_docs = []

    if analyses_collection is not None:
        try:
            query = {}
            if scan_type:
                query["type"] = scan_type.lower()
            cursor = analyses_collection.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit)
            raw_docs = list(cursor)
        except Exception as error:
            print(f"Error querying MongoDB, reading local fallback: {error}")
            raw_docs = []

    if not raw_docs:
        with _file_lock:
            if LOCAL_STORAGE_FILE.exists():
                try:
                    with open(LOCAL_STORAGE_FILE, "r", encoding="utf-8") as f:
                        all_local = json.load(f)
                    if scan_type:
                        raw_docs = [d for d in all_local if d.get("type", "").lower() == scan_type.lower()]
                    else:
                        raw_docs = all_local
                    raw_docs = raw_docs[:limit]
                except Exception as error:
                    print(f"Error reading local history: {error}")
                    raw_docs = []

    history = []
    for doc in raw_docs:
        item = _serialize_doc(doc)

        # Security constraint: NEVER store or return message plaintext; SHA-256 hash only.
        if item.get("type") == "message":
            item.pop("message", None)
            msg_hash = item.get("message_hash", "")
            item["target"] = f"Hash: {msg_hash[:12]}..." if msg_hash else "Message Scan"
        elif item.get("type") == "url":
            item["target"] = item.get("original_url", item.get("normalized_url", "URL Scan"))
        elif item.get("type") == "apk":
            item["target"] = item.get("app_name") or item.get("filename") or item.get("package_name") or "APK Scan"
        else:
            item["target"] = "Unknown Scan"

        history.append(item)

    return history


def get_aggregated_stats() -> dict:
    """Calculate aggregated stats for Reports tab from MongoDB or local storage."""
    docs = []

    is_mongo = False
    if analyses_collection is not None:
        try:
            docs = list(analyses_collection.find({}, {"_id": 0}))
            is_mongo = True
        except Exception:
            docs = []

    if not docs:
        with _file_lock:
            if LOCAL_STORAGE_FILE.exists():
                try:
                    with open(LOCAL_STORAGE_FILE, "r", encoding="utf-8") as f:
                        docs = json.load(f)
                except Exception:
                    docs = []

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
        "mongodb_connected": is_mongo,
        "storage_mode": "MongoDB" if is_mongo else "Local File Storage",
    }