"""Threat intelligence retrieval backed by Firecrawl and Supermemory Local.

This module is the only ClawNet integration point for web crawling and
Supermemory. It stores deterministic, normalized source evidence only; callers
receive structured records suitable for a policy decision or LLM explanation.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Protocol

try:
    from supermemory import Supermemory as _Supermemory
    _HAS_SUPERMEMORY = True
except ImportError:
    _HAS_SUPERMEMORY = False


_LOCAL_SERVER = "http://localhost:6767"
_DEFAULT_CACHE_TTL = 6 * 60 * 60
_DEFAULT_INTERVAL = 6 * 60 * 60
_DEFAULT_CACHE_PATH = Path.home() / ".clawnet" / "threat_cache.json"
_MAX_SUMMARY_CHARS = 600

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)
_URL_RE = re.compile(r"\bhttps?://[^\s<>()\[\]{}\"']+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE
)
_HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})\b")
_DATE_RE = re.compile(r"\b20\d{2}[-/]\d{2}[-/]\d{2}\b")
_CVSS_RE = re.compile(
    r"\b(?:CVSS(?:\s+(?:v?\d(?:\.\d)?))?(?:\s+(?:base\s+)?score)?|base\s+score)\s*[:=]?\s*(10(?:\.0)?|[0-9](?:\.\d)?)\b",
    re.IGNORECASE,
)
_AFFECTED_RE = re.compile(
    r"\b(?:affected\s+(?:products?|software|packages?|versions?)|"
    r"(?:affected\s+)?(?:product|software|package))\s*[:\-]\s*([^\n.;]{3,180})",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ThreatSource:
    """A trusted, public source that can be independently cached and ingested."""

    name: str
    url: str
    category: str


DEFAULT_SOURCES: tuple[ThreatSource, ...] = (
    ThreatSource(
        "CISA Known Exploited Vulnerabilities",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "cve",
    ),
    ThreatSource("NVD CVE Database", "https://nvd.nist.gov/vuln/search", "cve"),
    ThreatSource("MITRE ATT&CK", "https://attack.mitre.org/", "advisory"),
    ThreatSource(
        "GitHub Security Advisories", "https://github.com/advisories", "advisory"
    ),
    ThreatSource(
        "Microsoft Security Response Center",
        "https://msrc.microsoft.com/update-guide",
        "advisory",
    ),
    ThreatSource("Unit 42 Threat Research", "https://unit42.paloaltonetworks.com/", "malware"),
    ThreatSource("Malwarebytes Labs", "https://www.malwarebytes.com/blog", "malware"),
    ThreatSource("Cisco Talos Intelligence", "https://blog.talosintelligence.com/", "advisory"),
)


@dataclass
class FetchedPage:
    content: str
    metadata: dict[str, Any]


class CrawlProvider(Protocol):
    def scrape(self, source: ThreatSource) -> FetchedPage:
        """Return the source content without performing any interpretation."""


class FirecrawlProvider:
    """Small Firecrawl v2 adapter using the official HTTP API.

    Keeping this adapter here avoids a second crawler dependency and makes a
    future VirusTotal, OTX, or other provider an additive change.
    """

    _ENDPOINT = "https://api.firecrawl.dev/v2/scrape"

    def __init__(self, api_key: str, cache_ttl_seconds: int) -> None:
        self._api_key = api_key
        self._cache_ttl_ms = max(0, cache_ttl_seconds) * 1000

    def scrape(self, source: ThreatSource) -> FetchedPage:
        body = json.dumps(
            {
                "url": source.url,
                "formats": ["markdown"],
                "onlyMainContent": True,
                "maxAge": self._cache_ttl_ms,
                "storeInCache": True,
                "timeout": 30000,
                "blockAds": True,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self._ENDPOINT,
            data=body,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=35) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:160]
            raise RuntimeError(f"Firecrawl returned HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(f"Firecrawl request failed: {exc}") from exc

        if not payload.get("success", False):
            raise RuntimeError(str(payload.get("error") or "Firecrawl scrape failed"))
        data = payload.get("data") or {}
        content = data.get("markdown") or data.get("content") or ""
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("Firecrawl returned no readable content")
        metadata = data.get("metadata") or {}
        return FetchedPage(content=content, metadata=metadata if isinstance(metadata, dict) else {})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _clean_text(value: Any, limit: int = _MAX_SUMMARY_CHARS) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _unique(values: list[str], limit: int = 50) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        clean = _clean_text(value, 256)
        key = clean.lower()
        if clean and key not in seen:
            result.append(clean)
            seen.add(key)
        if len(result) >= limit:
            break
    return result


def _extract_ips(text: str) -> list[str]:
    candidates = re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text)
    ips: list[str] = []
    for candidate in candidates:
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if not parsed.is_private and not parsed.is_loopback and not parsed.is_unspecified:
            ips.append(str(parsed))
    return _unique(ips)


def _extract_urls_and_domains(text: str, source_url: str) -> tuple[list[str], list[str]]:
    urls = [match.rstrip(".,;:!?") for match in _URL_RE.findall(text)]
    source_host = urllib.parse.urlparse(source_url).hostname or ""
    domains = _DOMAIN_RE.findall(text)
    for url in urls:
        host = urllib.parse.urlparse(url).hostname
        if host:
            domains.append(host)
    domains = [domain.lower() for domain in domains if domain.lower() != source_host.lower()]
    return _unique(urls), _unique(domains)


def _publication_date(text: str, metadata: dict[str, Any]) -> str:
    for key in ("publishedTime", "publishedDate", "published", "date"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return _clean_text(value, 40)
    match = _DATE_RE.search(text)
    return match.group(0).replace("/", "-") if match else ""


def _summary(text: str) -> str:
    # Preserve source facts, but remove Markdown link targets and choose sentences
    # most likely to describe the advisory rather than navigation boilerplate.
    plain = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    plain = re.sub(r"[`#>*_]", " ", plain)
    sentences = [
        _clean_text(sentence, 320)
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", plain)
        if _clean_text(sentence, 320)
    ]
    preferred = [
        sentence
        for sentence in sentences
        if _CVE_RE.search(sentence)
        or re.search(r"\b(?:cvss|exploited|vulnerab|malware|advisory|security update)\b", sentence, re.I)
    ]
    chosen = preferred[:3] or sentences[:2]
    return _clean_text(" ".join(chosen), _MAX_SUMMARY_CHARS)


def _ioc_reputation(text: str, has_iocs: bool) -> str:
    if not has_iocs:
        return ""
    low = text.lower()
    if any(term in low for term in ("malicious", "malware", "command and control", "c2")):
        return "malicious"
    if any(term in low for term in ("known exploited", "actively exploited", "exploited in the wild")):
        return "known_exploited"
    return "reported"


def normalize_document(source: ThreatSource, page: FetchedPage) -> dict:
    """Convert one crawler response into deterministic, structured evidence."""
    text = page.content
    cves = _unique([match.upper() for match in _CVE_RE.findall(text)])
    urls, domains = _extract_urls_and_domains(text, source.url)
    hashes = _unique([match.lower() for match in _HASH_RE.findall(text)])
    ips = _extract_ips(text)
    affected = _unique(_AFFECTED_RE.findall(text), limit=20)
    cvss_match = _CVSS_RE.search(text)
    cvss = float(cvss_match.group(1)) if cvss_match else None
    low = text.lower()
    exploit_available = any(
        term in low
        for term in ("known exploited", "actively exploited", "exploited in the wild", "exploit available")
    )
    category = "cve" if cves and source.category == "cve" else source.category
    iocs = {"ips": ips, "domains": domains, "urls": urls, "hashes": hashes}
    document = {
        "schema": "clawnet.threat-intelligence/v1",
        "kind": "threat_intelligence",
        "category": category,
        "source": {"name": source.name, "url": source.url},
        "publication_date": _publication_date(text, page.metadata),
        "cves": cves,
        "iocs": iocs,
        "affected_software": affected,
        "cvss": cvss,
        "exploit_available": exploit_available,
        "ioc_reputation": _ioc_reputation(text, any(iocs.values())),
        "summary": _summary(text),
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    document["id"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    document["container_tags"] = _container_tags(document)
    return document


def _container_tags(document: dict) -> list[str]:
    tags = ["threat_feed", str(document.get("category") or "advisory")]
    if any((document.get("iocs") or {}).values()):
        tags.append("reputation")
    return _unique(tags, limit=3)


def _parse_document(value: Any) -> Optional[dict]:
    if not isinstance(value, str):
        return None
    try:
        document = json.loads(value)
    except (TypeError, ValueError):
        return None
    if not isinstance(document, dict):
        return None
    if document.get("schema") != "clawnet.threat-intelligence/v1":
        return None
    if document.get("kind") != "threat_intelligence":
        return None
    return document


class ThreatIntelligenceService:
    """Fetch, cache, store, and retrieve structured threat evidence."""

    def __init__(
        self,
        *,
        cache_path: Optional[Path] = None,
        crawler: Optional[CrawlProvider] = None,
        client: Any = None,
        cache_ttl_seconds: Optional[int] = None,
    ) -> None:
        self._cache_path = cache_path or Path(os.environ.get("CLAWNET_THREAT_CACHE_PATH", _DEFAULT_CACHE_PATH))
        self._cache_ttl = cache_ttl_seconds or int(
            os.environ.get("CLAWNET_THREAT_CACHE_TTL_SECONDS", _DEFAULT_CACHE_TTL)
        )
        self._lock = threading.Lock()
        self._cache = self._load_cache()
        # Circuit breaker: a configured-but-unreachable server must not stall the
        # verdict hot path (the SDK otherwise retries/times out for ~14s). We probe
        # the port cheaply and cache the result for a cooldown window.
        self._reach_ok_until = 0.0
        self._reach_bad_until = 0.0

        self._client = client if client is not None else self._make_client()
        if crawler is not None:
            self._crawler = crawler
        else:
            firecrawl_key = os.environ.get("FIRECRAWL_API_KEY", "")
            self._crawler = FirecrawlProvider(firecrawl_key, self._cache_ttl) if firecrawl_key else None

    @property
    def available(self) -> bool:
        return self._client is not None

    @property
    def can_update(self) -> bool:
        return self._crawler is not None

    def update(self, *, force: bool = False, sources: Optional[tuple[ThreatSource, ...]] = None) -> dict:
        """Fetch changed source pages and queue their normalized evidence in Supermemory."""
        selected = sources or DEFAULT_SOURCES
        report = {"fetched": 0, "cached": 0, "ingested": 0, "errors": [], "documents": []}
        if self._crawler is None:
            report["errors"].append("FIRECRAWL_API_KEY is not set")
            return report

        for source in selected:
            cached = self._cache.get("sources", {}).get(source.url, {})
            if not force and self._fresh(cached) and cached.get("document"):
                report["cached"] += 1
                report["documents"].append(cached["document"])
                continue
            try:
                page = self._crawler.scrape(source)
                document = normalize_document(source, page)
                self._cache.setdefault("sources", {})[source.url] = {
                    "fetched_at": _now_iso(),
                    "content_sha256": hashlib.sha256(page.content.encode("utf-8")).hexdigest(),
                    "document": document,
                }
                self._save_cache()
                report["fetched"] += 1
                report["documents"].append(document)
                if self._store(document):
                    report["ingested"] += 1
            except Exception as exc:
                report["errors"].append(f"{source.name}: {str(exc)[:180]}")
        return report

    def search(self, query: str, limit: int = 10) -> list[dict]:
        """Search Supermemory first, accepting only our structured evidence schema."""
        query = _clean_text(query, 300)
        if not query:
            return []
        documents: list[dict] = []
        if self._client is not None and self._server_reachable():
            try:
                response = self._client.search.memories(
                    q=query, limit=max(1, limit), rerank=True, search_mode="documents"
                )
                for result in getattr(response, "results", []) or []:
                    document = _parse_document(
                        getattr(result, "chunk", None) or getattr(result, "memory", None)
                    )
                    if document:
                        documents.append(document)
            except Exception:
                # The local fetch cache remains useful while Supermemory restarts.
                self._reach_bad_until = time.time() + 60
                self._reach_ok_until = 0.0

        # This is an exact keyword fallback over the crawl cache, not a second
        # vector database. Semantic retrieval is always attempted above first.
        for document in self._cached_matches(query):
            if len(documents) >= limit:
                break
            documents.append(document)
        return _dedupe_documents(documents)[:limit]

    def enrich(self, observable_type: str, value: str) -> dict:
        """Return the evidence needed to enrich a single IOC or package lookup."""
        value = _clean_text(value, 300)
        if not value:
            return _empty_enrichment(observable_type, value, self.available)
        documents = self.search(value, limit=12)
        direct = [doc for doc in documents if _document_mentions(doc, observable_type, value)]
        evidence = direct or documents
        return _build_enrichment(observable_type, value, evidence, self.available)

    def enrich_many(
        self,
        *,
        ips: Optional[list[str]] = None,
        domains: Optional[list[str]] = None,
        urls: Optional[list[str]] = None,
        hashes: Optional[list[str]] = None,
        processes: Optional[list[str]] = None,
        packages: Optional[list[str]] = None,
    ) -> dict:
        matches: dict[str, dict] = {}
        for observable_type, values in (
            ("ip", ips or []),
            ("domain", domains or []),
            ("url", urls or []),
            ("hash", hashes or []),
            ("process", processes or []),
            ("package", packages or []),
        ):
            for value in _unique([str(value) for value in values], limit=20):
                result = self.enrich(observable_type, value)
                if result["previous_evidence"]:
                    matches[f"{observable_type}:{value}"] = result

        evidence = _dedupe_documents(
            item
            for result in matches.values()
            for item in result.get("previous_evidence", [])
        )
        cves = _unique([cve for document in evidence for cve in document.get("cves", [])])
        reputations = [
            reputation
            for result in matches.values()
            for reputation in result.get("ioc_reputation", [])
            if isinstance(reputation, dict)
        ]
        hits = []
        for key, result in matches.items():
            source = _source_label(result.get("previous_evidence", [{}])[0])
            cve_text = ", ".join(result.get("matching_cves", [])[:3])
            hits.append(f"{key} matched {cve_text or 'threat evidence'} from {source}")
        return {
            "available": self.available,
            "matches": matches,
            "matching_cves": cves,
            "ioc_reputation": reputations,
            "hits": hits,
            "previous_evidence": evidence[:20],
        }

    def recent_cves(self, limit: int = 20) -> list[dict]:
        documents = self.search("recent CVE security advisory", limit=max(limit * 2, 20))
        cves = [document for document in documents if document.get("cves")]
        return sorted(cves, key=lambda item: item.get("publication_date", ""), reverse=True)[:limit]

    def _make_client(self):
        api_key = os.environ.get("SUPERMEMORY_API_KEY", "")
        if not (_HAS_SUPERMEMORY and api_key):
            return None
        try:
            # Fast-fail: no retry storms, bounded per-call time. Combined with the
            # reachability probe, a down server costs a fraction of a second.
            return _Supermemory(
                api_key=api_key,
                base_url=os.environ.get("SUPERMEMORY_API_URL", _LOCAL_SERVER),
                timeout=5.0,
                max_retries=0,
            )
        except Exception:
            return None

    def _server_reachable(self) -> bool:
        """Cheap TCP probe of the Supermemory port, cached for a cooldown window.

        Keeps a configured-but-down server from stalling the deterministic verdict
        path — we skip the SDK entirely and fall back to the local crawl cache.
        """
        import socket
        from urllib.parse import urlparse

        now = time.time()
        if now < self._reach_ok_until:
            return True
        if now < self._reach_bad_until:
            return False
        parsed = urlparse(os.environ.get("SUPERMEMORY_API_URL", _LOCAL_SERVER))
        host, port = parsed.hostname or "localhost", parsed.port or 6767
        try:
            socket.create_connection((host, port), timeout=0.4).close()
            self._reach_ok_until = now + 60
            return True
        except Exception:
            self._reach_bad_until = now + 60
            return False

    def _store(self, document: dict) -> bool:
        if self._client is None:
            return False
        content = json.dumps(document, sort_keys=True, separators=(",", ":"))
        source = document.get("source") or {}
        metadata = {
            "schema": document["schema"],
            "kind": document["kind"],
            "category": document.get("category", ""),
            "source": str(source.get("name", "")),
            "source_url": str(source.get("url", "")),
            "publication_date": document.get("publication_date", ""),
            "cves": document.get("cves", []),
            "exploit_available": bool(document.get("exploit_available")),
        }
        try:
            # `add` is the official Python SDK's document-ingestion helper.
            self._client.add(
                content=content,
                container_tags=document.get("container_tags", ["threat_feed"]),
                custom_id=document["id"],
                metadata=metadata,
            )
            return True
        except Exception:
            return False

    def _fresh(self, entry: dict) -> bool:
        fetched_at = entry.get("fetched_at", "")
        if not fetched_at:
            return False
        try:
            parsed = datetime.fromisoformat(fetched_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        return (datetime.now(timezone.utc) - parsed).total_seconds() < self._cache_ttl

    def _load_cache(self) -> dict:
        try:
            cache = json.loads(self._cache_path.read_text(encoding="utf-8"))
            if isinstance(cache, dict) and isinstance(cache.get("sources"), dict):
                return cache
        except Exception:
            pass
        return {"version": 1, "sources": {}}

    def _save_cache(self) -> None:
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._cache_path.write_text(json.dumps(self._cache, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _cached_matches(self, query: str) -> list[dict]:
        terms = [term for term in re.findall(r"[a-zA-Z0-9_.:-]{3,}", query.lower())]
        scored: list[tuple[int, dict]] = []
        for entry in self._cache.get("sources", {}).values():
            document = entry.get("document")
            if not isinstance(document, dict):
                continue
            blob = json.dumps(document, sort_keys=True).lower()
            score = sum(term in blob for term in terms)
            if score:
                scored.append((score, document))
        return [document for _, document in sorted(scored, key=lambda pair: pair[0], reverse=True)]


def _dedupe_documents(documents) -> list[dict]:
    unique: list[dict] = []
    ids: set[str] = set()
    for document in documents:
        if not isinstance(document, dict):
            continue
        document_id = str(document.get("id") or json.dumps(document, sort_keys=True))
        if document_id not in ids:
            ids.add(document_id)
            unique.append(document)
    return unique


def _document_mentions(document: dict, observable_type: str, value: str) -> bool:
    target = value.lower()
    iocs = document.get("iocs") or {}
    if observable_type == "ip":
        return target in {str(item).lower() for item in iocs.get("ips", [])}
    if observable_type == "domain":
        return target in {str(item).lower() for item in iocs.get("domains", [])}
    if observable_type == "url":
        return target in {str(item).lower() for item in iocs.get("urls", [])}
    if observable_type == "hash":
        return target in {str(item).lower() for item in iocs.get("hashes", [])}
    if observable_type == "package":
        return target in {str(item).lower() for item in document.get("affected_software", [])}
    return target in json.dumps(document, sort_keys=True).lower()


def _source_label(document: dict) -> str:
    source = document.get("source") or {}
    return _clean_text(source.get("name", "unknown source"), 80)


def _evidence_view(document: dict) -> dict:
    source = document.get("source") or {}
    return {
        "cves": list(document.get("cves") or [])[:20],
        "ioc_reputation": document.get("ioc_reputation", ""),
        "affected_software": list(document.get("affected_software") or [])[:10],
        "cvss": document.get("cvss"),
        "exploit_available": bool(document.get("exploit_available")),
        "publication_date": document.get("publication_date", ""),
        "source": {"name": source.get("name", ""), "url": source.get("url", "")},
        "summary": document.get("summary", ""),
    }


def _empty_enrichment(observable_type: str, value: str, available: bool) -> dict:
    return {
        "observable": {"type": observable_type, "value": value},
        "available": available,
        "matching_cves": [],
        "ioc_reputation": [],
        "malware_reports": [],
        "advisories": [],
        "previous_evidence": [],
        "related_incidents": [],
    }


def _build_enrichment(observable_type: str, value: str, documents: list[dict], available: bool) -> dict:
    result = _empty_enrichment(observable_type, value, available)
    evidence = [_evidence_view(document) for document in _dedupe_documents(documents)[:12]]
    result["previous_evidence"] = evidence
    result["matching_cves"] = _unique([cve for document in evidence for cve in document["cves"]])
    result["ioc_reputation"] = [
        {"value": value, "reputation": document["ioc_reputation"], "source": document["source"]}
        for document in evidence
        if document["ioc_reputation"]
    ]
    result["malware_reports"] = [
        document for document in evidence if _clean_text(document["source"].get("name", "")).lower().find("malware") >= 0
        or "malware" in _clean_text(document["summary"]).lower()
    ]
    result["advisories"] = [
        document for document in evidence if document["cves"] or document["exploit_available"]
    ]
    result["related_incidents"] = [
        {"cves": document["cves"], "publication_date": document["publication_date"], "source": document["source"]}
        for document in evidence
    ]
    return result


class ThreatIntelligenceAgent:
    """Periodic updater. It is opt-in through a configured Firecrawl key."""

    def __init__(self, service: ThreatIntelligenceService, interval_seconds: int) -> None:
        self._service = service
        self._interval = max(60, interval_seconds)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="clawnet-threat-intel", daemon=True)

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    def start(self) -> None:
        if not self.running:
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._service.update()
            self._stop.wait(self._interval)


_service: Optional[ThreatIntelligenceService] = None
_agent: Optional[ThreatIntelligenceAgent] = None
_global_lock = threading.Lock()


def _get_service() -> ThreatIntelligenceService:
    global _service
    with _global_lock:
        if _service is None:
            _service = ThreatIntelligenceService()
        return _service


def update_threat_intelligence(*, force: bool = False) -> dict:
    return _get_service().update(force=force)


def enrich_ip(ip: str) -> dict:
    return _get_service().enrich("ip", ip)


def enrich_domain(domain: str) -> dict:
    return _get_service().enrich("domain", domain)


def enrich_hash(file_hash: str) -> dict:
    return _get_service().enrich("hash", file_hash)


def enrich_url(url: str) -> dict:
    return _get_service().enrich("url", url)


def enrich_package(package: str) -> dict:
    return _get_service().enrich("package", package)


def enrich_observables(**kwargs) -> dict:
    return _get_service().enrich_many(**kwargs)


def search_memory(query: str, limit: int = 10) -> list[dict]:
    return _get_service().search(query, limit=limit)


def get_recent_cves(limit: int = 20) -> list[dict]:
    return _get_service().recent_cves(limit=limit)


def get_related_threats(query: str, limit: int = 10) -> list[dict]:
    return search_memory(query, limit=limit)


def start_threat_intelligence_agent(interval_seconds: Optional[int] = None) -> bool:
    """Start the periodic collector once when Firecrawl has been configured."""
    global _agent
    service = _get_service()
    if not service.can_update:
        return False
    interval = interval_seconds or int(os.environ.get("THREAT_INTEL_INTERVAL_SECONDS", _DEFAULT_INTERVAL))
    with _global_lock:
        if _agent is None or not _agent.running:
            _agent = ThreatIntelligenceAgent(service, interval)
            _agent.start()
    return True


def stop_threat_intelligence_agent() -> None:
    with _global_lock:
        if _agent is not None:
            _agent.stop()
