Implement a dedicated Threat Intelligence Agent in a single new file:

core/web_search.py

This file should contain all web search, threat intelligence ingestion, enrichment, caching, and SuperMemory integration logic. Keep the implementation modular so the rest of ClawNet simply imports and calls this module.

Requirements:

1. Build a background Threat Intelligence Agent that periodically fetches recent security intelligence using Firecrawl (free tier) as the primary web search/crawling engine.

2. Crawl trusted public security sources including:
- CISA Known Exploited Vulnerabilities
- NVD CVE Database
- MITRE ATT&CK
- GitHub Security Advisories
- Vendor security advisories
- Malware reports
- Public threat blogs

3. Normalize every fetched document into structured threat intelligence containing:
- CVE IDs
- IOCs (IPs, domains, URLs, hashes)
- affected software
- CVSS score
- exploit availability
- publication date
- source
- summary

4. Store all normalized intelligence inside SuperMemory so the local OpenClaw model can retrieve recent security knowledge without performing live web searches.

5. Build a local Threat Knowledge Base that continuously grows over time and persists between sessions.

6. Implement IOC enrichment APIs.

Given an:
- IP
- Domain
- URL
- File hash
- Process
- Package
- Dependency

search the local knowledge base first and return matching CVEs, advisories, malware reports, reputation, and related evidence.

7. Implement semantic retrieval so OpenClaw can query SuperMemory for relevant security context before generating explanations.

8. Cache all fetched intelligence locally to minimize repeated web requests and API usage.

9. Continuously refresh threat intelligence in the background (configurable interval) without blocking the monitoring UI.

10. Build a Threat Timeline so newly published CVEs and advisories are stored chronologically. If a sandboxed project contains an affected dependency, ClawNet should immediately reference the relevant CVE from memory.

11. Expose clean helper functions such as:

- update_threat_intelligence()
- enrich_ip(ip)
- enrich_domain(domain)
- enrich_hash(hash)
- enrich_url(url)
- enrich_package(package)
- search_memory(query)
- get_recent_cves()
- get_related_threats(query)

12. Integrate this module into the deterministic policy engine.

Before generating any verdict:
- enrich all evidence using web_search.py
- retrieve matching threat intelligence
- attach supporting evidence
- pass only structured evidence to OpenClaw

13. Replace opaque AI reasoning with evidence-backed explanations.

Every explanation should reference:
- matching CVEs
- matched IOC reputation
- advisory summaries
- threat intelligence source
- supporting evidence from SuperMemory

Never allow the LLM to invent security claims.

14. Integrate this module into the Chain of Trust pipeline:

Sandbox Report
→ Policy Engine
→ Signature Verification
→ SBOM Generation
→ Dependency Vulnerability Scan
→ Threat Intelligence Lookup (web_search.py)
→ Human Approval
→ Promote to Host

15. Make the implementation completely modular so future threat providers can be added easily without changing the rest of ClawNet.

All web search, crawling, normalization, caching, memory storage, enrichment, and retrieval logic should live exclusively inside core/web_search.py.