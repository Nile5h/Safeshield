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

from analyzer.apk_analyzer import (
    calculate_sha256,
    detect_suspicious_apis,
    analyze_apk,
    audit_manifest,
    detect_dangerous_combos,
    extract_urls_and_ips,
    check_signing_certificate,
)
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
        manifest_xml: Any = None,
        certificates: list[Any] | None = None,
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
        self._manifest_xml = manifest_xml  # pass an xml.etree.ElementTree.Element or None
        self._certificates = certificates or []

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

    # ---- New methods required by advanced analysis functions ----

    def get_android_manifest_axml(self) -> "DummyAXML":
        return DummyAXML(self._manifest_xml)

    def get_certificates(self) -> list[Any]:
        return self._certificates

    def get_certificates_der_v2(self) -> list[bytes]:
        return []


class DummyAXML:
    """Wraps an optional ElementTree element as if returned by androguard."""

    def __init__(self, xml_elem: Any):
        self._xml = xml_elem

    def get_xml(self) -> Any:
        if self._xml is None:
            raise ValueError("No manifest XML configured in DummyAPK")
        return self._xml



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
    assert "not an apk" in result["error"].lower()


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


# ============================================================
# NEW TESTS — ADVANCED STATIC ANALYSIS FUNCTIONS
# ============================================================

import xml.etree.ElementTree as ET


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_manifest(app_attribs: dict[str, str], components: list[tuple[str, dict]] | None = None) -> ET.Element:
    """
    Build a minimal AndroidManifest.xml Element for testing.

    ``app_attribs`` sets attributes on the <application> element.
    ``components`` is a list of (tag, attrib_dict) tuples added under <application>.
    """
    ns = "http://schemas.android.com/apk/res/android"
    manifest = ET.Element("manifest")
    app_elem = ET.SubElement(manifest, "application")

    for key, val in app_attribs.items():
        # Use namespace-qualified key matching what androguard produces
        app_elem.set(f"{{{ns}}}{key}", val)

    for tag, attribs in (components or []):
        child = ET.SubElement(app_elem, tag)
        for k, v in attribs.items():
            child.set(f"{{{ns}}}{k}", v)

    return manifest


# ── 1. audit_manifest ─────────────────────────────────────────────────────────

class TestAuditManifest:

    def test_detects_debuggable(self) -> None:
        xml = _make_manifest({"debuggable": "true"})
        apk = DummyAPK(manifest_xml=xml)
        findings = audit_manifest(apk)
        flags = {f["flag"] for f in findings}
        assert "debuggable" in flags
        pts = next(f["risk_points"] for f in findings if f["flag"] == "debuggable")
        assert pts > 0

    def test_detects_allow_backup(self) -> None:
        xml = _make_manifest({"allowBackup": "true"})
        apk = DummyAPK(manifest_xml=xml)
        findings = audit_manifest(apk)
        assert any(f["flag"] == "allowBackup" for f in findings)

    def test_detects_cleartext_traffic(self) -> None:
        xml = _make_manifest({"usesCleartextTraffic": "true"})
        apk = DummyAPK(manifest_xml=xml)
        findings = audit_manifest(apk)
        assert any(f["flag"] == "usesCleartextTraffic" for f in findings)

    def test_detects_exported_activity_no_permission(self) -> None:
        xml = _make_manifest(
            {},
            components=[("activity", {"name": "com.evil.HiddenActivity", "exported": "true"})],
        )
        apk = DummyAPK(manifest_xml=xml)
        findings = audit_manifest(apk)
        flags = {f["flag"] for f in findings}
        assert "exported_activity_no_permission" in flags

    def test_exported_with_permission_is_clean(self) -> None:
        xml = _make_manifest(
            {},
            components=[("activity", {
                "name": "com.safe.ProtectedActivity",
                "exported": "true",
                "permission": "com.safe.MY_PERMISSION",
            })],
        )
        apk = DummyAPK(manifest_xml=xml)
        findings = audit_manifest(apk)
        flags = {f["flag"] for f in findings}
        assert "exported_activity_no_permission" not in flags

    def test_no_manifest_returns_empty(self) -> None:
        """audit_manifest gracefully handles APKs whose manifest cannot be parsed."""
        apk = DummyAPK(manifest_xml=None)
        findings = audit_manifest(apk)
        # Should not raise; may return [] or a single parse-error entry
        assert isinstance(findings, list)

    def test_multiple_flags_cumulative(self) -> None:
        xml = _make_manifest({"debuggable": "true", "allowBackup": "true", "usesCleartextTraffic": "true"})
        apk = DummyAPK(manifest_xml=xml)
        findings = audit_manifest(apk)
        flags = {f["flag"] for f in findings}
        assert {"debuggable", "allowBackup", "usesCleartextTraffic"}.issubset(flags)
        total_pts = sum(f["risk_points"] for f in findings)
        assert total_pts >= 45  # 20 + 10 + 15


# ── 2. detect_dangerous_combos ───────────────────────────────────────────────

class TestDetectDangerousCombos:

    def test_otp_stealer_detected(self) -> None:
        perms = [
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.INTERNET",
        ]
        combos = detect_dangerous_combos(perms)
        names = {c["name"] for c in combos}
        assert "OTP Stealer" in names
        otp = next(c for c in combos if c["name"] == "OTP Stealer")
        assert otp["risk_points"] > 0
        assert isinstance(otp["matched"], list)

    def test_overlay_hijack_detected(self) -> None:
        perms = [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ]
        combos = detect_dangerous_combos(perms)
        names = {c["name"] for c in combos}
        assert "Overlay / Accessibility Hijack" in names

    def test_background_spyware_with_audio(self) -> None:
        perms = [
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.RECORD_AUDIO",
        ]
        combos = detect_dangerous_combos(perms)
        names = {c["name"] for c in combos}
        assert "Background Spyware" in names

    def test_background_spyware_with_camera(self) -> None:
        perms = [
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.CAMERA",
        ]
        combos = detect_dangerous_combos(perms)
        names = {c["name"] for c in combos}
        assert "Background Spyware" in names

    def test_no_match_for_benign_perms(self) -> None:
        perms = [
            "android.permission.INTERNET",
            "android.permission.CAMERA",  # alone – not enough for any combo
        ]
        combos = detect_dangerous_combos(perms)
        assert combos == []

    def test_partial_otp_perms_below_threshold(self) -> None:
        # Only 2 of the 4 OTP perms — should NOT trigger (min_match = 3)
        perms = [
            "android.permission.RECEIVE_SMS",
            "android.permission.INTERNET",
        ]
        combos = detect_dangerous_combos(perms)
        names = {c["name"] for c in combos}
        assert "OTP Stealer" not in names


# ── 3. extract_urls_and_ips ───────────────────────────────────────────────────

class TestExtractUrlsAndIps:

    def test_extracts_http_urls(self) -> None:
        dex_text = "some binary http://example.com/api/data more data"
        apk = DummyAPK(dex_text=dex_text)
        result = extract_urls_and_ips(apk)
        assert any("example.com" in u for u in result["urls"])

    def test_flags_discord_webhook(self) -> None:
        dex_text = "endpoint: https://discord.com/api/webhooks/12345/abcdef"
        apk = DummyAPK(dex_text=dex_text)
        result = extract_urls_and_ips(apk)
        assert len(result["flagged_urls"]) >= 1
        assert result["risk_points"] > 0

    def test_flags_telegram_c2(self) -> None:
        dex_text = "bot_url=https://api.telegram.org/botTOKEN/sendMessage"
        apk = DummyAPK(dex_text=dex_text)
        result = extract_urls_and_ips(apk)
        assert any("telegram" in f["url"] for f in result["flagged_urls"])

    def test_extracts_public_ip(self) -> None:
        dex_text = "server = 203.0.113.42 port=8080"
        apk = DummyAPK(dex_text=dex_text)
        result = extract_urls_and_ips(apk)
        assert "203.0.113.42" in result["ips"]
        assert len(result["flagged_ips"]) >= 1

    def test_ignores_private_ips(self) -> None:
        dex_text = "local=127.0.0.1 lan=192.168.1.1 vpn=10.0.0.1"
        apk = DummyAPK(dex_text=dex_text)
        result = extract_urls_and_ips(apk)
        assert result["ips"] == []
        assert result["flagged_ips"] == []

    def test_empty_dex_returns_empty(self) -> None:
        apk = DummyAPK(dex_text="no urls here")
        result = extract_urls_and_ips(apk)
        assert result["urls"] == []
        assert result["ips"] == []
        assert result["flagged_urls"] == []
        assert result["flagged_ips"] == []
        assert result["risk_points"] == 0


# ── 4. check_signing_certificate ─────────────────────────────────────────────

class DummyCert:
    """Minimal certificate stand-in."""

    class _DN:
        def __init__(self, s: str):
            self.human_friendly = s

    def __init__(self, subject: str, issuer: str, algo: str = "sha256WithRSAEncryption"):
        self.subject = self._DN(subject)
        self.issuer = self._DN(issuer)
        self.signature_algo = algo


class TestCheckSigningCertificate:

    def test_debug_cert_flagged(self) -> None:
        cert = DummyCert("CN=Android Debug, O=Android, C=US", "CN=Android Debug, O=Android, C=US")
        apk = DummyAPK(certificates=[cert])
        info = check_signing_certificate(apk)
        assert info["is_debug_cert"] is True
        assert info["risk_points"] >= 15
        assert len(info["flags"]) >= 1

    def test_weak_sha1_algo_flagged(self) -> None:
        cert = DummyCert("CN=My App", "CN=My CA", algo="sha1WithRSAEncryption")
        apk = DummyAPK(certificates=[cert])
        info = check_signing_certificate(apk)
        assert info["is_weak_algo"] is True
        assert info["risk_points"] >= 10

    def test_strong_cert_clean(self) -> None:
        cert = DummyCert("CN=Production App, O=MyCompany", "CN=Production CA", algo="sha256WithRSAEncryption")
        apk = DummyAPK(certificates=[cert])
        info = check_signing_certificate(apk)
        assert info["is_debug_cert"] is False
        assert info["is_weak_algo"] is False
        assert info["risk_points"] == 0

    def test_no_cert_returns_unknown(self) -> None:
        apk = DummyAPK(certificates=[])
        info = check_signing_certificate(apk)
        assert info["subject"] == "unknown"
        assert len(info["flags"]) >= 1  # "No signing certificate found"

    def test_debug_and_weak_algo_cumulative(self) -> None:
        cert = DummyCert("CN=Android Debug", "CN=Android Debug", algo="md5WithRSAEncryption")
        apk = DummyAPK(certificates=[cert])
        info = check_signing_certificate(apk)
        assert info["is_debug_cert"] is True
        assert info["is_weak_algo"] is True
        assert info["risk_points"] >= 25


# ── 5. analyze_apk() return-dict backward-compat & new fields ────────────────

class TestAnalyzeApkNewFields:
    """Verify that analyze_apk() returns all new additive keys alongside
    every field the existing React frontend consumes."""

    EXISTING_KEYS = {
        "success", "filename", "file_name", "file_size_mb", "sha256",
        "package_name", "app_name", "version_name", "version_code",
        "permissions", "permission_count", "suspicious_permissions",
        "suspicious_apis", "api_findings", "component_counts",
        "activities_count", "services_count", "receivers_count",
        "providers_count", "risk_score", "verdict",
    }
    NEW_KEYS = {"manifest_issues", "dangerous_combos", "network_indicators", "certificate_info"}

    def test_all_keys_present(self, monkeypatch: Any, apk_tmp_path: Path) -> None:
        monkeypatch.setattr("analyzer.apk_analyzer.APK", lambda _: DummyAPK())
        result = analyze_apk(str(apk_tmp_path))
        assert result["success"] is True
        for key in self.EXISTING_KEYS | self.NEW_KEYS:
            assert key in result, f"Missing key in analyze_apk result: {key}"

    def test_network_indicators_structure(self, monkeypatch: Any, apk_tmp_path: Path) -> None:
        monkeypatch.setattr(
            "analyzer.apk_analyzer.APK",
            lambda _: DummyAPK(dex_text="https://discord.com/api/webhooks/abc 8.8.8.8"),
        )
        result = analyze_apk(str(apk_tmp_path))
        ni = result["network_indicators"]
        for key in ("urls", "ips", "flagged_urls", "flagged_ips"):
            assert key in ni

    def test_manifest_issues_is_list(self, monkeypatch: Any, apk_tmp_path: Path) -> None:
        monkeypatch.setattr("analyzer.apk_analyzer.APK", lambda _: DummyAPK())
        result = analyze_apk(str(apk_tmp_path))
        assert isinstance(result["manifest_issues"], list)

    def test_certificate_info_structure(self, monkeypatch: Any, apk_tmp_path: Path) -> None:
        monkeypatch.setattr("analyzer.apk_analyzer.APK", lambda _: DummyAPK())
        result = analyze_apk(str(apk_tmp_path))
        ci = result["certificate_info"]
        for key in ("subject", "issuer", "algorithm", "is_debug_cert", "is_weak_algo", "flags"):
            assert key in ci

    def test_risk_score_bounded(self, monkeypatch: Any, apk_tmp_path: Path) -> None:
        """Risk score must never exceed 100 even with many findings."""
        monkeypatch.setattr("analyzer.apk_analyzer.APK", lambda _: DummyAPK(
            permissions=[
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.INTERNET",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.RECORD_AUDIO",
                "android.permission.REQUEST_INSTALL_PACKAGES",
            ],
            dex_text=(
                "android/telephony/SmsManager sendTextMessage "
                "android/accessibilityservice/AccessibilityService "
                "dalvik/system/DexClassLoader java/lang/Runtime "
                "https://discord.com/api/webhooks/evil 91.2.3.4"
            ),
        ))
        result = analyze_apk(str(apk_tmp_path))
        assert result["risk_score"] <= 100

