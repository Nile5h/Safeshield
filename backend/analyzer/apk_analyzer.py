from pathlib import Path
import hashlib

from loguru import logger
from androguard.core.apk import APK


# ============================================================
# DISABLE ANDROGUARD DEBUG LOGS
# ============================================================

logger.remove()
logger.add(
    lambda msg: None,
    level="WARNING"
)


# ============================================================
# SHA-256
# ============================================================

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


# ============================================================
# SUSPICIOUS PERMISSIONS
# ============================================================

SUSPICIOUS_PERMISSIONS = {

    "android.permission.READ_SMS": 15,
    "android.permission.RECEIVE_SMS": 15,
    "android.permission.SEND_SMS": 15,

    "android.permission.CALL_PHONE": 10,

    "android.permission.READ_CALL_LOG": 10,
    "android.permission.WRITE_CALL_LOG": 10,

    "android.permission.READ_CONTACTS": 5,
    "android.permission.WRITE_CONTACTS": 5,

    "android.permission.RECORD_AUDIO": 10,

    "android.permission.CAMERA": 5,

    "android.permission.ACCESS_FINE_LOCATION": 10,
    "android.permission.ACCESS_COARSE_LOCATION": 5,

    "android.permission.READ_PHONE_STATE": 10,

    "android.permission.REQUEST_INSTALL_PACKAGES": 20,

    "android.permission.SYSTEM_ALERT_WINDOW": 15,

    "android.permission.RECEIVE_BOOT_COMPLETED": 10,

    "android.permission.BIND_ACCESSIBILITY_SERVICE": 25,
}


# ============================================================
# SUSPICIOUS API / CODE INDICATORS
SUSPICIOUS_APIS = {

    # ========================================================
    # HIGH RISK
    # ========================================================

    "android/telephony/SmsManager": (
        20,
        "SMS sending capability detected"
    ),

    "sendTextMessage": (
        20,
        "SMS sending API detected"
    ),

    "android/accessibilityservice/AccessibilityService": (
        25,
        "Accessibility service detected"
    ),

    "dalvik/system/DexClassLoader": (
        20,
        "Dynamic code loading detected"
    ),

    "java/lang/ProcessBuilder": (
        15,
        "Process execution capability detected"
    ),

    "java/lang/Runtime": (
        10,
        "Runtime execution capability detected"
    ),

    # ========================================================
    # MEDIUM RISK
    # ========================================================

    "android/view/WindowManager": (
        5,
        "Window management capability detected"
    ),

    # ========================================================
    # LOW RISK
    # These are common in legitimate applications.
    # ========================================================

    "java/net/HttpURLConnection": (
        1,
        "Network communication detected"
    ),

    "okhttp3": (
        1,
        "OkHttp networking library detected"
    ),

    "android/webkit/WebView": (
        1,
        "WebView usage detected"
    )
}



# ============================================================
# SEARCH APK DEX FOR SUSPICIOUS INDICATORS
# ============================================================

def detect_suspicious_apis(apk):

    findings = []

    try:

        dex_files = apk.get_all_dex()

        for dex in dex_files:

            dex_text = dex.decode(
                "utf-8",
                errors="ignore"
            )

            for indicator, data in SUSPICIOUS_APIS.items():

                points, description = data

                if indicator in dex_text:

                    # Avoid duplicate findings
                    already_found = any(
                        f["indicator"] == indicator
                        for f in findings
                    )

                    if not already_found:

                        findings.append({
                            "indicator": indicator,
                            "risk_points": points,
                            "description": description
                        })

    except Exception as e:

        findings.append({
            "indicator": "analysis_error",
            "risk_points": 0,
            "description": str(e)
        })

    return findings


# ============================================================
# APK ANALYZER
# ============================================================

def analyze_apk(file_path: str):

    path = Path(file_path)

    # --------------------------------------------------------
    # FILE VALIDATION
    # --------------------------------------------------------

    if not path.exists():
        return {
            "success": False,
            "error": "APK file not found"
        }

    if path.suffix.lower() != ".apk":
        return {
            "success": False,
            "error": "File is not an APK"
        }

    try:

        # ----------------------------------------------------
        # BASIC FILE INFORMATION
        # ----------------------------------------------------

        sha256 = calculate_sha256(str(path))

        file_size_mb = round(
            path.stat().st_size / (1024 * 1024),
            2
        )

        # ----------------------------------------------------
        # PARSE APK
        # ----------------------------------------------------

        apk = APK(str(path))

        # ----------------------------------------------------
        # BASIC APK INFORMATION
        # ----------------------------------------------------

        package_name = apk.get_package()
        app_name = apk.get_app_name()
        version_name = apk.get_androidversion_name()
        version_code = apk.get_androidversion_code()

        # ----------------------------------------------------
        # PERMISSIONS
        # ----------------------------------------------------

        permissions = apk.get_permissions()

        suspicious_permissions = []

        risk_score = 0

        for permission in permissions:

            if permission in SUSPICIOUS_PERMISSIONS:

                points = SUSPICIOUS_PERMISSIONS[permission]

                suspicious_permissions.append({
                    "permission": permission,
                    "risk_points": points
                })

                risk_score += points

        # ----------------------------------------------------
        # API ANALYSIS
        # ----------------------------------------------------

        api_findings = detect_suspicious_apis(apk)

        for finding in api_findings:

            risk_score += finding["risk_points"]

        # ----------------------------------------------------
        # APK COMPONENTS
        # ----------------------------------------------------

        activities = apk.get_activities()
        services = apk.get_services()
        receivers = apk.get_receivers()
        providers = apk.get_providers()

        # ----------------------------------------------------
        # COMPONENT RISK SIGNALS
        # ----------------------------------------------------

        if len(services) >= 3:
            risk_score += 5

        if len(receivers) >= 5:
            risk_score += 5

        if len(providers) >= 3:
            risk_score += 5

        # ----------------------------------------------------
        # LIMIT SCORE
        # ----------------------------------------------------

        risk_score = min(risk_score, 100)

        # ----------------------------------------------------
        # VERDICT
        # ----------------------------------------------------

        if risk_score >= 60:

            verdict = "dangerous"

        elif risk_score >= 30:

            verdict = "suspicious"

        else:

            verdict = "low_risk"

        # ----------------------------------------------------
        # RESULT
        # ----------------------------------------------------

        component_counts = {
            "activities": len(activities),
            "services": len(services),
            "receivers": len(receivers),
            "providers": len(providers),
        }

        return {

            "success": True,
            "filename": path.name,
            "file_name": path.name,
            "file_size_mb": file_size_mb,
            "sha256": sha256,
            "package_name": package_name,
            "app_name": app_name,
            "version_name": version_name,
            "version_code": version_code,
            "permissions": permissions,
            "permission_count": len(permissions),
            "suspicious_permissions": suspicious_permissions,
            "suspicious_apis": [
                {
                    "indicator": item["indicator"],
                    "risk_points": item["risk_points"],
                    "description": item["description"],
                }
                for item in api_findings
            ],
            "api_findings": api_findings,
            "component_counts": component_counts,
            "activities_count": len(activities),
            "services_count": len(services),
            "receivers_count": len(receivers),
            "providers_count": len(providers),
            "risk_score": risk_score,
            "verdict": verdict,
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }