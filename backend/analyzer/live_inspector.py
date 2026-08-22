"""
live_inspector.py – Timeout-bounded HTTP fetcher for SafeShield URL analysis.

Fetches page headers and HTML body within a strict 3-second wall-clock budget.
All exceptions are caught; live inspection is purely additive —
static ML + rule heuristics always run first and the result is always valid.
"""

from __future__ import annotations

import re
import time

# ── Constants ──────────────────────────────────────────────────────────────────
FETCH_TIMEOUT = 3           # seconds total (connect + read)
MAX_BODY_BYTES = 512_000    # 512 KB cap — enough for full HTML, avoids huge blobs
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_HEADERS = {
    "User-Agent": _UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "close",
}

# Content-Type values that signal a binary / executable payload
MALICIOUS_CONTENT_TYPES = frozenset({
    "application/x-msdownload",
    "application/x-executable",
    "application/x-msdos-program",
    "application/octet-stream",
    "application/x-sh",
    "application/vnd.android.package-archive",
    "application/x-bat",
    "application/x-msi",
    "application/zip",
    "application/x-rar-compressed",
    "application/x-7z-compressed",
    "application/x-iso9660-image",
})

# Executable extensions checked in Content-Disposition and download links
MALICIOUS_EXTENSIONS = frozenset({
    ".exe", ".bat", ".apk", ".scr", ".msi", ".iso", ".zip",
    ".rar", ".ps1", ".jar", ".vbs", ".hta", ".dll", ".cab",
    ".cmd", ".com", ".pif", ".lnk",
})


def _empty_result() -> dict:
    return {
        "reachable": False,
        "status_code": None,
        "content_type": "",
        "server": "",
        "html": "",
        "response_url": "",
        "response_time_ms": 0,
        "suspicious_content_type": False,
        "error": None,
    }


def fetch_page(url: str) -> dict:
    """
    Attempt a GET request within FETCH_TIMEOUT seconds.

    Returns a plain dict with keys:
        reachable (bool)               – False on any network/timeout error
        status_code (int | None)
        content_type (str)             – raw Content-Type header value
        server (str)                   – Server header, if present
        html (str)                     – body (truncated to MAX_BODY_BYTES)
        response_url (str)             – final URL after redirects
        response_time_ms (int)         – round-trip duration in milliseconds
        suspicious_content_type (bool) – True when Content-Type signals a payload
        error (str | None)             – sanitised error message if reachable=False
    """
    result = _empty_result()
    t_start = time.perf_counter()
    try:
        import requests  # local import keeps module usable without requests installed

        resp = requests.get(
            url,
            headers=_HEADERS,
            timeout=FETCH_TIMEOUT,
            stream=True,           # don't buffer large bodies eagerly
            allow_redirects=True,
            verify=True,           # enforce TLS certificate validation
        )

        result["response_time_ms"] = round((time.perf_counter() - t_start) * 1000)
        result["reachable"] = True
        result["status_code"] = resp.status_code
        result["response_url"] = resp.url

        ct = resp.headers.get("Content-Type", "").lower()
        result["content_type"] = ct

        server = resp.headers.get("Server", "")
        result["server"] = server

        # Flag malicious Content-Type immediately, without reading the body
        ct_base = ct.split(";")[0].strip()
        if ct_base in MALICIOUS_CONTENT_TYPES:
            result["suspicious_content_type"] = True

        # Only read the body for HTML/text responses
        if "text/html" in ct or "text/plain" in ct or ct_base == "":
            body = b""
            for chunk in resp.iter_content(chunk_size=8192):
                body += chunk
                if len(body) >= MAX_BODY_BYTES:
                    break
            result["html"] = body.decode("utf-8", errors="replace")

    except ImportError:
        result["response_time_ms"] = round((time.perf_counter() - t_start) * 1000)
        result["error"] = "requests library not available"
    except Exception as exc:
        result["response_time_ms"] = round((time.perf_counter() - t_start) * 1000)
        result["error"] = _sanitise_error(str(exc))

    return result


def _sanitise_error(msg: str) -> str:
    """Strip credentials that might appear in error messages."""
    return re.sub(r"(https?://)[^@\s]+@", r"\1[redacted]@", msg)[:200]
