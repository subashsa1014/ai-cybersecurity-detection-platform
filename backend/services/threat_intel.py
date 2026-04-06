"""
Threat Intelligence Service for VirusTotal and AbuseIPDB integration.
"""
import httpx
import hashlib
import re
from typing import Optional, Tuple, Dict, Any
from functools import lru_cache
from config import settings


class ThreatIntelService:
    """Service for querying external threat intelligence APIs."""

    def __init__(self):
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        self.abuse_api_key = settings.ABUSEIPDB_API_KEY
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.abuse_base_url = "https://api.abuseipdb.com/api/v2"

    async def _make_request(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
    ) -> dict:
        """Make an async HTTP request with error handling."""
        try:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            return {"error": str(e), "status_code": e.response.status_code}
        except httpx.RequestError:
            return {"error": "Network error"}

    async def check_url_virustotal(self, url: str) -> Tuple[float, dict]:
        """Check a URL against VirusTotal. Returns (score, details)."""
        if not self.vt_api_key:
            return 0.0, {"available": False, "reason": "No API key"}
        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {"x-apikey": self.vt_api_key}
            url_id = hashlib.sha256(url.encode()).hexdigest()
            result = await self._make_request(
                client,
                f"{self.vt_base_url}/urls/{url_id}",
                headers,
            )
            if "error" in result:
                return 0.0, {"available": False, "error": result["error"]}
            data = result.get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            if total == 0:
                return 0.0, {"available": True, "checked": False}
            score = ((malicious * 3 + suspicious) / total) * 100
            return score, {
                "available": True,
                "checked": True,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "score": score,
            }

    async def check_hash_virustotal(self, file_hash: str) -> dict:
        """Check a file hash against VirusTotal."""
        if not self.vt_api_key:
            return {"available": False, "score": 0}
        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {"x-apikey": self.vt_api_key}
            result = await self._make_request(
                client,
                f"{self.vt_base_url}/files/{file_hash}",
                headers,
            )
            if "error" in result:
                if result.get("status_code") == 404:
                    return {"available": True, "checked": False, "score": 0}
                return {"available": False, "score": 0, "error": result["error"]}
            data = result.get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            score = ((malicious * 3 + suspicious) / total) * 100 if total else 0
            return {
                "available": True,
                "checked": True,
                "malicious": malicious,
                "suspicious": suspicious,
                "score": score,
            }

    async def check_ip_abuseipdb(self, url: str) -> Tuple[float, dict]:
        """Check the IP address in a URL against AbuseIPDB."""
        if not self.abuse_api_key:
            return 0.0, {"available": False, "reason": "No API key"}
        ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url)
        if not ip_match:
            domain_match = re.search(r"//([^/]+)", url)
            if not domain_match:
                return 0.0, {"available": True, "checked": False}
            domain = domain_match.group(1)
            if domain in ("localhost", "127.0.0.1"):
                return 0.0, {"available": True, "checked": False}
            return 0.0, {"available": True, "checked": False, "reason": "No IP in URL"}
        ip_address = ip_match.group()
        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {
                "Key": self.abuse_api_key,
                "Accept": "application/json",
            }
            result = await self._make_request(
                client,
                f"{self.abuse_base_url}/check",
                headers,
                params={"ipAddress": ip_address, "maxAgeInDays": 90},
            )
            if "error" in result:
                return 0.0, {"available": False, "error": result["error"]}
            data = result.get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            return (
                abuse_score,
                {
                    "available": True,
                    "checked": True,
                    "abuse_score": abuse_score,
                    "total_reports": total_reports,
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "country_code": data.get("countryCode", ""),
                },
            )
