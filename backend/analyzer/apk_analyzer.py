from pathlib import Path
import hashlib
import re

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

    "android.permission.INTERNET": 0,
}


# ============================================================
# DANGEROUS PERMISSION COMBOS — MALWARE SIGNATURES
# ============================================================

DANGEROUS_COMBOS = [
    {
        "name": "OTP Stealer",
        "required": {
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.INTERNET",
        },
        # Partial match: any two of the SMS perms + the other two
        "min_match": 3,
        "risk_points": 30,
        "description": (
            "OTP/SMS stealer signature: app requests SMS access, "
            "auto-start on boot, and internet access — a classic "
            "banking-trojan pattern."
        ),
    },
    {
        "name": "Overlay / Accessibility Hijack",
        "required": {
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        },
        "min_match": 2,
        "risk_points": 35,
        "description": (
            "Overlay + accessibility service combo: app can draw over "
            "other apps and intercept UI events — hallmark of credential-"
            "harvesting overlays."
        ),
    },
    {
        "name": "Background Spyware",
        "required": {
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.ACCESS_FINE_LOCATION",
        },
        "any_of": {
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
        },
        "min_match": 3,
        "risk_points": 35,
        "description": (
            "Background spyware signature: auto-starts on boot, tracks "
            "precise location, and records audio or captures camera — "
            "typical stalkerware / RAT behaviour."
        ),
    },
]


# ============================================================
# C2 / WEBHOOK HOST INDICATORS
# ============================================================

SUSPICIOUS_WEBHOOK_HOSTS = {
    "discord.com",
    "discordapp.com",
    "discord.gg",
    "hooks.slack.com",
    "api.telegram.org",
    "t.me",
    "webhook.site",
    "pipedream.net",
    "requestbin.com",
    "ngrok.io",
    "ngrok-free.app",
    "serveo.net",
    "localhost.run",
}

# Compiled once for performance
_URL_RE = re.compile(
    r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,}",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
# Private / loopback ranges we want to ignore
_PRIVATE_IP_RE = re.compile(
    r"^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)"
)


# ============================================================
# SIGNING CERTIFICATE INDICATORS
# ============================================================

# Common DNs that appear in AOSP / SDK default debug keystores
DEBUG_CERT_SUBJECTS = {
    "CN=Android Debug",
    "CN=Android Debug, O=Android, C=US",
    "O=Android",
    "OU=Android",
    "C=US, O=Android",
}

WEAK_HASH_ALGORITHMS = {
    "md5withrsa",
    "md5withrsaencryption",
    "sha1withrsa",
    "sha1withrsaencryption",
    "sha1withdsa",
    "md2withrsa",
}


# ============================================================
# SUSPICIOUS API / CODE INDICATORS
# ============================================================

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
# 1. MANIFEST SECURITY AUDIT
# ============================================================

def audit_manifest(apk) -> list[dict]:
    """
    Inspect AndroidManifest.xml for dangerous flags and exported
    components that lack a permission guard.

    Returns a list of finding dicts:
        {
            "flag":        str,   # machine-readable identifier
            "description": str,
            "risk_points": int,
        }
    """
    findings = []

    try:
        # androguard exposes the parsed manifest XML element
        manifest_xml = apk.get_android_manifest_axml().get_xml()
    except Exception:
        # Some minimal/stub APKs have no parseable manifest — skip gracefully
        return findings

    try:
        # --------------------------------------------------------
        # A) Dangerous application-level flags
        # --------------------------------------------------------

        app_elems = manifest_xml.findall(".//application")
        for app in app_elems:
            attribs = app.attrib

            # Normalise namespace prefix — androguard may or may not include it
            def _attr(name: str) -> str | None:
                for key, val in attribs.items():
                    if key.endswith(name):
                        return val
                return None

            if _attr("debuggable") == "true":
                findings.append({
                    "flag": "debuggable",
                    "description": (
                        "Application is marked debuggable=true. "
                        "Attackers can attach a debugger to the running process."
                    ),
                    "risk_points": 20,
                })

            if _attr("allowBackup") == "true":
                findings.append({
                    "flag": "allowBackup",
                    "description": (
                        "allowBackup=true allows ADB backups of app data "
                        "without root — private databases and tokens may leak."
                    ),
                    "risk_points": 10,
                })

            if _attr("usesCleartextTraffic") == "true":
                findings.append({
                    "flag": "usesCleartextTraffic",
                    "description": (
                        "usesCleartextTraffic=true permits unencrypted HTTP "
                        "traffic — credentials/tokens sent in plaintext."
                    ),
                    "risk_points": 15,
                })

        # --------------------------------------------------------
        # B) Exported components without a permission guard
        # --------------------------------------------------------

        COMPONENT_TAGS = ("activity", "service", "receiver", "provider")

        for tag in COMPONENT_TAGS:
            for elem in manifest_xml.findall(f".//{tag}"):
                attribs = elem.attrib

                def _attr_e(name: str) -> str | None:  # noqa: E306
                    for key, val in attribs.items():
                        if key.endswith(name):
                            return val
                    return None

                exported = _attr_e("exported")
                permission = _attr_e("permission")

                # exported="true" with no permission attribute
                if exported == "true" and not permission:
                    comp_name = _attr_e("name") or tag
                    findings.append({
                        "flag": f"exported_{tag}_no_permission",
                        "description": (
                            f"Exported {tag} '{comp_name}' has no android:permission "
                            "guard — any app on the device can interact with it."
                        ),
                        "risk_points": 8,
                    })

    except Exception as exc:
        findings.append({
            "flag": "manifest_parse_error",
            "description": str(exc),
            "risk_points": 0,
        })

    return findings


# ============================================================
# 2. DANGEROUS PERMISSION COMBO DETECTION
# ============================================================

def detect_dangerous_combos(permissions: list[str]) -> list[dict]:
    """
    Check the flat permission list against known malware signature
    combos and return matched signatures.

    Returns a list of matched combo dicts:
        {
            "name":        str,
            "matched":     list[str],  # which perms were present
            "risk_points": int,
            "description": str,
        }
    """
    perm_set = set(permissions)
    matched = []

    for combo in DANGEROUS_COMBOS:
        required = combo["required"]
        any_of = combo.get("any_of", set())
        min_match = combo["min_match"]

        # Count how many required perms are present
        present_required = required & perm_set
        present_any = any_of & perm_set if any_of else set()

        total_present = len(present_required) + (1 if present_any else 0)

        if total_present >= min_match:
            matched.append({
                "name": combo["name"],
                "matched": sorted(present_required | present_any),
                "risk_points": combo["risk_points"],
                "description": combo["description"],
            })

    return matched


# ============================================================
# 3. C2 & URL EXTRACTION
# ============================================================

def extract_urls_and_ips(apk) -> dict:
    """
    Scan DEX bytecode strings for hardcoded HTTP/HTTPS URLs and
    bare IPv4 addresses. Flag direct-IP comms and suspicious
    webhook/C2 endpoints.

    Returns:
        {
            "urls":         list[str],   # all unique URLs found
            "ips":          list[str],   # all unique public IPs found
            "flagged_urls": list[dict],  # URLs hitting webhook hosts
            "flagged_ips":  list[dict],  # direct-IP communication hits
            "risk_points":  int,
        }
    """
    all_urls: set[str] = set()
    all_ips: set[str] = set()
    flagged_urls: list[dict] = []
    flagged_ips: list[dict] = []
    risk_points = 0

    try:
        dex_files = apk.get_all_dex()
    except Exception:
        dex_files = []

    for dex in dex_files:
        try:
            text = dex.decode("utf-8", errors="ignore")
        except Exception:
            continue

        # -- URLs --
        for url in _URL_RE.findall(text):
            # Strip trailing junk chars that often creep in from binary context
            url = url.rstrip("\"',;)")
            all_urls.add(url)

            try:
                # Quick hostname extraction without urllib overhead
                host_part = url.split("://", 1)[1].split("/")[0].split("?")[0].lower()
                host = host_part.split(":")[0]  # remove port
            except IndexError:
                host = ""

            if host in SUSPICIOUS_WEBHOOK_HOSTS:
                if not any(f["url"] == url for f in flagged_urls):
                    flagged_urls.append({
                        "url": url,
                        "reason": f"Suspicious C2/webhook host: {host}",
                        "risk_points": 20,
                    })
                    risk_points += 20

        # -- Bare IPv4 addresses --
        for ip in _IPV4_RE.findall(text):
            if _PRIVATE_IP_RE.match(ip):
                continue  # ignore loopback / RFC-1918
            all_ips.add(ip)

    # Any direct public-IP communication is suspicious
    for ip in all_ips:
        flagged_ips.append({
            "ip": ip,
            "reason": "Direct IP-address communication (no domain name)",
            "risk_points": 10,
        })
        risk_points += 10

    # Cap network risk contribution
    risk_points = min(risk_points, 40)

    return {
        "urls": sorted(all_urls),
        "ips": sorted(all_ips),
        "flagged_urls": flagged_urls,
        "flagged_ips": flagged_ips,
        "risk_points": risk_points,
    }


# ============================================================
# 4. SIGNING CERTIFICATE CHECK
# ============================================================

def check_signing_certificate(apk) -> dict:
    """
    Inspect the APK's signing certificate(s) for:
      - Known Android debug keystore subjects
      - Weak / deprecated hashing algorithms (MD5, SHA-1)

    Returns:
        {
            "subject":         str,
            "issuer":          str,
            "algorithm":       str,
            "is_debug_cert":   bool,
            "is_weak_algo":    bool,
            "flags":           list[str],   # human-readable warnings
            "risk_points":     int,
        }
    """
    result = {
        "subject": "unknown",
        "issuer": "unknown",
        "algorithm": "unknown",
        "is_debug_cert": False,
        "is_weak_algo": False,
        "flags": [],
        "risk_points": 0,
    }

    try:
        # androguard >= 3.x: get_certificates() returns a list of
        # asn1crypto Certificate objects
        certs = apk.get_certificates()
        if not certs:
            # Try v2/v3 scheme
            certs = []
            for block in (apk.get_certificates_der_v2() or []):
                try:
                    from asn1crypto import pem as asn1_pem, x509 as asn1_x509
                    cert = asn1_x509.Certificate.load(block)
                    certs.append(cert)
                except Exception:
                    pass

        if not certs:
            result["flags"].append("No signing certificate found")
            return result

        cert = certs[0]

        # Subject / Issuer — androguard wraps these as Certificate objects
        try:
            subject_dn = cert.subject.human_friendly
        except Exception:
            subject_dn = str(cert.subject)

        try:
            issuer_dn = cert.issuer.human_friendly
        except Exception:
            issuer_dn = str(cert.issuer)

        try:
            algo = cert.signature_algo
        except Exception:
            algo = "unknown"

        result["subject"] = subject_dn
        result["issuer"] = issuer_dn
        result["algorithm"] = algo

        # ---- Debug certificate check ----
        for debug_fragment in DEBUG_CERT_SUBJECTS:
            if debug_fragment.lower() in subject_dn.lower():
                result["is_debug_cert"] = True
                result["flags"].append(
                    f"Debug certificate detected (subject contains '{debug_fragment}'). "
                    "Never ship production apps signed with the debug keystore."
                )
                result["risk_points"] += 15
                break

        # ---- Weak algorithm check ----
        if algo.lower().replace("-", "") in WEAK_HASH_ALGORITHMS:
            result["is_weak_algo"] = True
            result["flags"].append(
                f"Weak signing algorithm: {algo}. "
                "SHA-1/MD5 signatures are deprecated and cryptographically broken."
            )
            result["risk_points"] += 10

    except Exception as exc:
        result["flags"].append(f"Certificate inspection error: {exc}")

    return result


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

                if points > 0:
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

        # ====================================================
        # NEW: MANIFEST SECURITY AUDIT
        # ====================================================

        manifest_issues = audit_manifest(apk)

        for issue in manifest_issues:
            risk_score += issue["risk_points"]

        # ====================================================
        # NEW: DANGEROUS PERMISSION COMBO DETECTION
        # ====================================================

        dangerous_combos = detect_dangerous_combos(permissions)

        for combo in dangerous_combos:
            risk_score += combo["risk_points"]

        # ====================================================
        # NEW: C2 & URL EXTRACTION
        # ====================================================

        network_indicators = extract_urls_and_ips(apk)

        risk_score += network_indicators["risk_points"]

        # ====================================================
        # NEW: SIGNING CERTIFICATE CHECK
        # ====================================================

        certificate_info = check_signing_certificate(apk)

        risk_score += certificate_info["risk_points"]

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

            # ---- Existing fields (API contract preserved) ----
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

            # ---- New additive fields ----
            "manifest_issues": manifest_issues,
            "dangerous_combos": dangerous_combos,
            "network_indicators": {
                "urls": network_indicators["urls"],
                "ips": network_indicators["ips"],
                "flagged_urls": network_indicators["flagged_urls"],
                "flagged_ips": network_indicators["flagged_ips"],
            },
            "certificate_info": {
                "subject": certificate_info["subject"],
                "issuer": certificate_info["issuer"],
                "algorithm": certificate_info["algorithm"],
                "is_debug_cert": certificate_info["is_debug_cert"],
                "is_weak_algo": certificate_info["is_weak_algo"],
                "flags": certificate_info["flags"],
            },
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }