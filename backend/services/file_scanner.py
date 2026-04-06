"""File malware scanning service using signature-based and heuristic detection."""

import hashlib
import re
from typing import Dict, List, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass
@dataclass
class ScanResult:
    """Result of a file scan."""
    filename: str
    is_safe: bool
    threats: List[str]
    risk_level: str
    risk_score: int
    hashes: Dict[str, str]
    file_size: int
    scanned_at: str



class FileScanner:
    """Malware file scanner using signature matching and heuristic analysis."""

    MALICIOUS_PATTERNS = [
        rb"eval\s*\(",
        rb"exec\s*\(",
        rb"base64_decode\s*\(",
        rb"gzinflate\s*\(",
        rb"system\s*\(",
        rb"shell_exec\s*\(",
        rb"passthru\s*\(",
        rb"popen\s*\(",
        rb"pcntl_exec\s*\(",
        rb"curl_exec\s*\(",
        rb"file_get_contents\s*\(\s*[\"\']http",
        rb"wget\s+http",
        rb"chmod\s+777",
        rb"<script[^>]*>.*</script>",
        rb"document\.cookie",
        rb"window\.location",
        rb"onerror\s*=",
        rb"onload\s*=",
        rb"iframe[^>]*src",
        rb"<object[^>]*data",
        rb"vbscript:",
        rb"javascript:",
        rb"<\?php\s+eval",
        rb"assert\s*\(",
        rb"preg_replace\s*\(\s*[\"\']/e",
        rb"include\s*\(",
        rb"require\s*\(",
        rb"fopen\s*\(\s*[\"\']https?://",
        rb"socket_connect",
        rb"stream_socket_client",
    ]

    MALWARE_EXTENSIONS = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".msi", ".scr", ".pif",
        ".com", ".hta", ".cpl", ".msp", ".reg", ".lnk"
    }

    SUSPICIOUS_EXTENSIONS = {
        ".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl", ".sh",
        ".py", ".rb", ".jar", ".apk", ".ipa", ".dmg"
    }

    KNOWN_HASHES = {
        "e4d909c290d0fb1ca068ffaddf22cbd0": "EICAR Test File (Safe)",
    }

    def __init__(self):
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
            for pattern in self.MALICIOUS_PATTERNS
        ]

    def calculate_hash(self, file_content: bytes) -> Dict[str, str]:
        return {
            "md5": hashlib.md5(file_content).hexdigest(),
            "sha1": hashlib.sha1(file_content).hexdigest(),
            "sha256": hashlib.sha256(file_content).hexdigest(),
        }

    def check_known_hashes(self, hashes: Dict[str, str]) -> Tuple[bool, str]:
        for hash_type, hash_value in hashes.items():
            if hash_value in self.KNOWN_HASHES:
                return True, self.KNOWN_HASHES[hash_value]
        return False, ""

    def check_extension(self, filename: str) -> Tuple[str, str]:
        ext = filename.lower()
        if not ext.startswith("."):
            ext = "." + ext.split(".")[-1] if "." in ext else ""
        else:
            ext = ext.split(".")[-1] if "." in ext else ""
        ext = "." + ext if ext else ""

        if ext in self.MALWARE_EXTENSIONS:
            return "high", f"Known malicious file type: {ext}"
        elif ext in self.SUSPICIOUS_EXTENSIONS:
            return "medium", f"Suspicious file type: {ext}"
        else:
            return "low", "Unknown file type"

    def scan_content(self, file_content: bytes) -> Tuple[int, List[str]]:
        matches = []
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(file_content):
                matches.append(f"Pattern {i + 1}: {self.MALICIOUS_PATTERNS[i].decode('utf-8', errors='ignore')}")

        match_count = len(matches)
        if match_count >= 5:
            return 100, matches
        elif match_count >= 3:
            return 70, matches
        elif match_count >= 1:
            return 40, matches
        else:
            return 0, []

    def scan(self, filename: str, file_content: bytes) -> Dict:
        hashes = self.calculate_hash(file_content)
        is_known, known_name = self.check_known_hashes(hashes)

        if is_known:
            return {
                "filename": filename,
                "is_malicious": False,
                "risk_level": "safe",
                "risk_score": 0,
                "reasons": [f"Known file: {known_name}"],
                "hashes": hashes,
            }

        ext_risk, ext_reason = self.check_extension(filename)
        content_score, content_matches = self.scan_content(file_content)

        score = content_score
        reasons = content_matches.copy()

        if ext_risk == "high":
            score += 30
            reasons.append(ext_reason)
        elif ext_risk == "medium":
            score += 15
            reasons.append(ext_reason)

        if len(file_content) == 0:
            score += 10
            reasons.append("Empty file")
        elif len(file_content) > 10 * 1024 * 1024:
            score += 5
            reasons.append("Very large file (>10MB)")

        score = min(score, 100)

        if score >= 70:
            risk_level = "high"
        elif score >= 40:
            risk_level = "medium"
        elif score >= 15:
            risk_level = "low"
        else:
            risk_level = "safe"

        is_malicious = risk_level in ["high", "medium"]

        return {
            "filename": filename,
            "is_malicious": is_malicious,
            "risk_level": risk_level,
            "risk_score": score,
            "reasons": reasons,
            "hashes": hashes,
            "file_size": len(file_content),
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }
            def scan_file(self, filename: str, file_obj) -> ScanResult:
        """Scan a file and return a ScanResult."""
        content = file_obj.read()
        if hasattr(file_obj, 'seek'):
            file_obj.seek(0)
        result = self.scan(filename, content)
        return ScanResult(
            filename=result["filename"],
            is_safe=not result["is_malicious"],
            threats=result["reasons"],
            risk_level=result["risk_level"],
            risk_score=result["risk_score"],
            hashes=result["hashes"],
            file_size=result["file_size"],
            scanned_at=result["scanned_at"],
        )



scanner = FileScanner()
