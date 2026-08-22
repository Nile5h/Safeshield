"""Comprehensive tests and benchmark runner for the SafeShield APK analyzer.

This suite covers both unit-level APK parsing logic and the FastAPI integration
endpoint at POST /analyze/apk. It uses fake APK objects and synthetic metadata so
it can run in CI/offline environments without requiring real APK binaries.
"""

from __future__ import annotations

import hashlib
import io
import os
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from analyzer.apk_analyzer import calculate_sha256, detect_suspicious_apis, analyze_apk
from main import app


CLIENT = TestClient(app)
BACKEND_DIR = Path(__file__).resolve().parent
TEST_APKS_DIR = BACKEND_DIR / "test_apks"


class DummyAPK:
    """Minimal APK stand-in for offline unit tests."""

    def __init__(
        self,
        *,
        package_name: str = "com.example.safeapp",
        app_name: str = "SafeApp",
        version_name: str = "1.2.3",
        version_code: int = 42,
        permissions: list[str] | None = None,
        activities: list[str] | None = None,
        services: list[str] | None = None,
        receivers: list[str] | None = None,
        providers: list[str] | None = None,
        dex_text: str = "",
    ):
        self._package_name = package_name
        self._app_name = app_name
        self._version_name = version_name
        self._version_code = version_code
        self._permissions = permissions or [
            "android.permission.INTERNET",
            "android.permission.READ_CONTACTS",
        ]
        self._activities = activities or ["MainActivity"]
        self._services = services or ["BackgroundService", "SyncService", "JobService"]
        self._receivers = receivers or ["BootReceiver", "SmsReceiver", "AlarmReceiver", "GeoReceiver", "InstallReceiver"]
        self._providers = providers or ["ProviderA", "ProviderB", "ProviderC"]
        self._dex_text = dex_text or (
            "android/telephony/SmsManager sendTextMessage android/accessibilityservice/AccessibilityService java/lang/Runtime"
        )

    def get_package(self) -> str:
        return self._package_name

    def get_app_name(self) -> str:
        return self._app_name

    def get_androidversion_name(self) -> str:
        return self._version_name

    def get_androidversion_code(self) -> int:
        return self._version_code

    def get_permissions(self) -> list[str]:
        return self._permissions

    def get_activities(self) -> list[str]:
        return self._activities

    def get_services(self) -> list[str]:
        return self._services

    def get_receivers(self) -> list[str]:
        return self._receivers

    def get_providers(self) -> list[str]:
        return self._providers

    def get_all_dex(self) -> list[bytes]:
        return [self._dex_text.encode("utf-8")]


@pytest.fixture
def dummy_apk() -> DummyAPK:
    return DummyAPK(
        permissions=[
            "android.permission.INTERNET",
            "android.permission.READ_CONTACTS",
            "android.permission.RECEIVE_SMS",
            "android.permission.CALL_PHONE",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        activities=["MainActivity", "LandingActivity"],
        services=["BackgroundService", "SyncService", "JobService"],
        receivers=["BootReceiver", "SmsReceiver", "AlarmReceiver", "GeoReceiver", "InstallReceiver"],
        providers=["ProviderA", "ProviderB", "ProviderC"],
    )


@pytest.fixture
def apk_tmp_path(tmp_path: Path) -> Path:
    """Create a minimal APK-like file so analyze_apk() can accept it."""
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"PK\x03\x04fake-apk-data")
    return apk_path


@pytest.fixture
def monkeypatched_apk(monkeypatch: Any, dummy_apk: DummyAPK) -> None:
    monkeypatch.setattr("analyzer.apk_analyzer.APK", lambda _: dummy_apk)


def test_calculate_sha256() -> None:
    payload = b"hello-safe-shield"
    file_path = Path("tmp_sha256_test.bin")
    try:
        file_path.write_bytes(payload)
        expected = hashlib.sha256(payload).hexdigest()
        assert calculate_sha256(str(file_path)) == expected
    finally:
        if file_path.exists():
            file_path.unlink()


def test_detect_suspicious_apis(dummy_apk: DummyAPK) -> None:
    findings = detect_suspicious_apis(dummy_apk)
    indicators = {item["indicator"] for item in findings}

    assert "android/telephony/SmsManager" in indicators
    assert "sendTextMessage" in indicators
    assert "android/accessibilityservice/AccessibilityService" in indicators
    assert any(item["indicator"] == "java/lang/Runtime" for item in findings)


def test_analyze_apk_unit_logic(monkeypatched_apk: None, apk_tmp_path: Path) -> None:
    result = analyze_apk(str(apk_tmp_path))

    assert result["success"] is True
    assert result["filename"] == apk_tmp_path.name
    assert result["package_name"] == "com.example.safeapp"
    assert result["app_name"] == "SafeApp"
    assert result["version_name"] == "1.2.3"
    assert result["version_code"] == 42

    assert "android.permission.RECEIVE_SMS" in {p["permission"] for p in result["suspicious_permissions"]}
    assert "android.permission.CALL_PHONE" in {p["permission"] for p in result["suspicious_permissions"]}

    suspicious_indicators = {item["indicator"] for item in result["suspicious_apis"]}
    assert "android/telephony/SmsManager" in suspicious_indicators
    assert "sendTextMessage" in suspicious_indicators

    assert result["component_counts"]["services"] >= 3
    assert result["component_counts"]["receivers"] >= 5
    assert result["component_counts"]["providers"] >= 3

    assert 0 <= result["risk_score"] <= 100
    assert result["verdict"] in {"low_risk", "suspicious", "dangerous"}


@pytest.mark.parametrize(
    "score, expected",
    [
        (10, "low_risk"),
        (30, "suspicious"),
        (59, "suspicious"),
        (60, "dangerous"),
        (99, "dangerous"),
    ],
)
def test_risk_verdict_boundaries(score: int, expected: str) -> None:
    assert ("dangerous" if score >= 60 else "suspicious" if score >= 30 else "low_risk") == expected


def test_analyze_apk_rejects_non_apk(tmp_path: Path) -> None:
    file_path = tmp_path / "notes.txt"
    file_path.write_text("not an apk", encoding="utf-8")

    result = analyze_apk(str(file_path))
    assert result["success"] is False
    assert "not an APK" in result["error"].lower()


def test_analyze_apk_rejects_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.apk"

    result = analyze_apk(str(missing))
    assert result["success"] is False
    assert "not found" in result["error"].lower()


def test_apk_api_upload_success(monkeypatch: Any) -> None:
    fake_result = {
        "success": True,
        "filename": "demo.apk",
        "sha256": "abc123",
        "package_name": "com.test.demo",
        "version_name": "2.0",
        "version_code": 20,
        "permissions": ["android.permission.INTERNET"],
        "suspicious_permissions": [],
        "suspicious_apis": [],
        "component_counts": {"activities": 1, "services": 0, "receivers": 0, "providers": 0},
        "risk_score": 10,
        "verdict": "low_risk",
    }
    monkeypatch.setattr("main.analyze_apk", lambda _: fake_result)

    response = CLIENT.post(
        "/analyze/apk",
        files={"file": ("demo.apk", io.BytesIO(b"fake apk data"), "application/vnd.android.package-archive")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "demo.apk"
    assert data["sha256"] == "abc123"
    assert data["package_name"] == "com.test.demo"
    assert data["version_name"] == "2.0"
    assert data["version_code"] == 20
    assert data["permissions"] == ["android.permission.INTERNET"]
    assert data["component_counts"]["activities"] == 1
    assert 0 <= data["risk_score"] <= 100
    assert data["verdict"] in {"low_risk", "suspicious", "dangerous"}


def test_apk_api_rejects_non_apk_upload() -> None:
    response = CLIENT.post(
        "/analyze/apk",
        files={"file": ("notes.txt", io.BytesIO(b"i am not an apk"), "text/plain")},
    )

    assert response.status_code == 400
    assert "valid apk" in response.json()["detail"].lower()


def test_apk_api_rejects_missing_file_field() -> None:
    response = CLIENT.post(
        "/analyze/apk",
        files={"wrong_name": ("demo.apk", io.BytesIO(b"fake apk"), "application/vnd.android.package-archive")},
    )

    assert response.status_code == 422


def test_apk_api_cleans_temp_files(monkeypatch: Any) -> None:
    seen_paths: list[str] = []

    def fake_analyze_apk(path: str) -> dict[str, Any]:
        seen_paths.append(path)
        assert os.path.exists(path)
        assert path.endswith(".apk")
        return {
            "success": True,
            "filename": "clean.apk",
            "sha256": "hash",
            "package_name": "com.clean",
            "version_name": "1.0",
            "version_code": 1,
            "permissions": [],
            "suspicious_permissions": [],
            "suspicious_apis": [],
            "component_counts": {"activities": 0, "services": 0, "receivers": 0, "providers": 0},
            "risk_score": 0,
            "verdict": "low_risk",
        }

    monkeypatch.setattr("main.analyze_apk", fake_analyze_apk)

    response = CLIENT.post(
        "/analyze/apk",
        files={"file": ("clean.apk", io.BytesIO(b"x"), "application/vnd.android.package-archive")},
    )

    assert response.status_code == 200
    assert seen_paths
    for temp_path in seen_paths:
        assert not os.path.exists(temp_path)


def _benchmark_apk(path: str) -> dict[str, Any]:
    started = time.perf_counter()
    result = analyze_apk(path)
    elapsed = time.perf_counter() - started
    return {
        "path": Path(path).name,
        "success": bool(result.get("success")),
        "risk_score": result.get("risk_score", 0),
        "verdict": result.get("verdict", "low_risk"),
        "elapsed_sec": round(elapsed, 4),
        "package_name": result.get("package_name", "unknown"),
    }


def run_benchmark(apk_dir: str | Path | None = None) -> None:
    """CLI benchmark runner for real APK files.

    Usage:
        python backend/test_apk_analyzer.py --apk-dir backend/test_apks
    """
    if apk_dir is None:
        apk_dir = TEST_APKS_DIR

    apk_dir = Path(apk_dir)
    apk_files = sorted(apk_dir.glob("*.apk")) if apk_dir.exists() else []

    if not apk_files:
        print(f"No APK files found in: {apk_dir}")
        return

    rows = [_benchmark_apk(str(apk)) for apk in apk_files]
    headers = ("APK", "Package", "Verdict", "Risk", "Time (s)")
    print("\nAPK Benchmark Summary")
    print("-" * 90)
    print(f"{headers[0]:<25} {headers[1]:<25} {headers[2]:<12} {headers[3]:>6} {headers[4]:>10}")
    for row in rows:
        print(
            f"{row['path']:<25} "
            f"{row['package_name']:<25} "
            f"{row['verdict']:<12} "
            f"{row['risk_score']:>6} "
            f"{row['elapsed_sec']:>10.4f}"
        )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SafeShield APK analyzer benchmark")
    parser.add_argument("--apk-dir", type=str, default=str(TEST_APKS_DIR), help="Directory containing APK files to scan")
    args = parser.parse_args()
    run_benchmark(args.apk_dir)
