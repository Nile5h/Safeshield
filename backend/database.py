import os
from pathlib import Path

from dotenv import load_dotenv
from pymongo import MongoClient

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "safeshield")

client = None
analyses_collection = None
if MONGODB_URI:
    client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    db = client[MONGODB_DATABASE]
    analyses_collection = db["analyses"]


def test_database_connection():
    if client is None:
        return False
    try:
        client.admin.command("ping")
        return True
    except Exception as error:
        print(f"MongoDB connection failed: {error}")
        return False