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
