"""Offline checks for threat-intelligence normalization and retrieval."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

import policy
import web_search 


class _Crawler:
    def __init__(self) -> None:
        self.calls = 0

    def scrape(self, source):
        self.calls += 1
        return web_search.FetchedPage(
            content=(
                "CVE-2025-12345 is actively exploited in the wild. CVSS: 9.8. "
                "Affected package: demo-package. Malware infrastructure used IP "
                "45.33.32.156 and domain evil.example.com with hash " + "a" * 64
            ),
            metadata={"publishedDate": "2025-03-01"},
        )


class _Search:
    def __init__(self, client) -> None:
        self._client = client

    def memories(self, **_kwargs):
        return SimpleNamespace(
            results=[SimpleNamespace(chunk=content, memory=None) for content in self._client.documents]
        )


class _Client:
    def __init__(self) -> None:
        self.documents = []
        self.added = []
        self.search = _Search(self)

    def add(self, **kwargs):
        self.added.append(kwargs)
        self.documents.append(kwargs["content"])


def test_threat_intelligence_uses_structured_supermemory_evidence(tmp_path):
    crawler = _Crawler()
    client = _Client()
    service = web_search.ThreatIntelligenceService(
        cache_path=tmp_path / "threat_cache.json",
        crawler=crawler,
        client=client,
        cache_ttl_seconds=3600,
    )
    source = web_search.ThreatSource("Test Advisory", "https://trusted.example/advisory", "advisory")

    report = service.update(sources=(source,))
    assert report["fetched"] == 1
    assert report["ingested"] == 1
    assert crawler.calls == 1
    assert client.added[0]["container_tags"] == ["threat_feed", "advisory", "reputation"]

    # The local fetch cache prevents a second Firecrawl request for unchanged content.
    cached = service.update(sources=(source,))
    assert cached["cached"] == 1
    assert crawler.calls == 1

    enriched = service.enrich("ip", "45.33.32.156")
    assert enriched["matching_cves"] == ["CVE-2025-12345"]
    assert enriched["ioc_reputation"][0]["reputation"] == "malicious"
    assert enriched["previous_evidence"][0]["publication_date"] == "2025-03-01"

    aggregate = service.enrich_many(ips=["45.33.32.156"], packages=["demo-package"])
    assert aggregate["matching_cves"] == ["CVE-2025-12345"]
    assert aggregate["ioc_reputation"][0]["reputation"] == "malicious"

    evidence = policy.Evidence(remote="45.33.32.156", foreign=True, threat_intelligence=aggregate)
    payload = policy.llm_payload(evidence, policy.evaluate(evidence))
    assert payload["threat_intelligence"]["matching_cves"] == ["CVE-2025-12345"]
    assert "CVE-2025-12345" in str(payload)


_SERP_MD = """\
## Organic Results

| # | Title | Snippet | Source |
| --- | --- | --- | --- |
| 1 | [CVE-2025-12345 advisory](https://vendor.example/cve-2025-12345) | CVE-2025-12345 is actively exploited in the wild. CVSS: 9.8. | Vendor |
| 2 | [Patch notes](https://news.example/patch) | Security update for demo-package. | News |
"""


class _SerpApiClient:
    """Stands in for `serpapi.Client`; records the params it was called with."""

    calls: list = []
    response = _SERP_MD

    def __init__(self, *, api_key=None, timeout=None):
        self.api_key = api_key

    def search(self, params):
        _SerpApiClient.calls.append(params)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class _SearchingCrawler(_Crawler):
    def __init__(self) -> None:
        super().__init__()
        self.searches = []

    def search(self, query, limit=10):
        self.searches.append(query)
        return [web_search._web_document("firecrawl", "Firecrawl hit", "https://fc.example/a",
                                         f"{query} seen in a malware campaign")]


def _live_service(tmp_path, monkeypatch, response):
    monkeypatch.setenv("SERPAPI_KEY", "test-key")
    monkeypatch.setitem(sys.modules, "serpapi", SimpleNamespace(Client=_SerpApiClient))
    monkeypatch.setattr(_SerpApiClient, "calls", [])
    monkeypatch.setattr(_SerpApiClient, "response", response)
    crawler = _SearchingCrawler()
    service = web_search.ThreatIntelligenceService(
        cache_path=tmp_path / "threat_cache.json", crawler=crawler, client=_Client(),
    )
    return service, crawler


def test_search_uses_serpapi_first(tmp_path, monkeypatch):
    service, crawler = _live_service(tmp_path, monkeypatch, _SERP_MD)

    results = service.search("CVE-2025-12345")

    assert _SerpApiClient.calls == [{"engine": "google", "q": "CVE-2025-12345", "output": "md"}]
    assert crawler.searches == []
    assert [r["provider"] for r in results] == ["serpapi", "serpapi"]
    assert results[0]["source"]["url"] == "https://vendor.example/cve-2025-12345"
    assert results[0]["cves"] == ["CVE-2025-12345"]
    assert results[0]["exploit_available"] is True


def test_search_falls_back_to_firecrawl_then_cache(tmp_path, monkeypatch):
    service, crawler = _live_service(tmp_path, monkeypatch, RuntimeError("quota exhausted"))

    results = service.search("45.33.32.156")
    assert len(_SerpApiClient.calls) == 1
    assert crawler.searches == ["45.33.32.156"]
    assert [r["provider"] for r in results] == ["firecrawl"]
    # A snippet saying "malware" must not become an IOC reputation verdict.
    assert service.enrich("ip", "45.33.32.156")["ioc_reputation"] == []

    # Both live providers down: the existing stored-evidence path still answers.
    service.update(sources=(web_search.ThreatSource("Test Advisory", "https://trusted.example/a", "advisory"),))
    crawler.search = lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("firecrawl down"))
    results = service.search("45.33.32.156")
    assert results and {r["provider"] for r in results} == {"cache"}
