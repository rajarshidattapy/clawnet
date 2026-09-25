Implement a dedicated Threat Intelligence Agent in a single new file:

core/web_search.py

This module should be the only place responsible for web crawling, threat intelligence ingestion, Supermemory Local integration, caching, enrichment, and retrieval. All other ClawNet modules should consume this module through clean helper APIs.

Requirements:

1. Integrate Supermemory Local using the official Python SDK.

Connect to the local server:

- base_url=http://localhost:6767
- API key loaded from environment

Do not build a custom vector database or memory implementation.

2. Build a background Threat Intelligence Agent that periodically fetches recent security intelligence using Firecrawl (free tier) as the primary crawler.

3. Crawl trusted public sources including:

- CISA Known Exploited Vulnerabilities
- NVD CVE Database
- MITRE ATT&CK
- GitHub Security Advisories
- Vendor security advisories
- Malware reports
- Public security blogs

4. Normalize every fetched document into structured threat intelligence containing:

- CVE IDs
- IOCs (IPs, domains, URLs, hashes)
- affected software
- CVSS score
- exploit availability
- publication date
- source
- summary

5. Store every normalized document inside Supermemory Local using the official SDK.

Use appropriate container tags such as:

- threat_feed
- cve
- malware
- advisory
- reputation

Store only structured evidence, never arbitrary LLM-generated text.

6. Build a persistent local Threat Knowledge Base using Supermemory.

The database should survive restarts and continuously grow as new threat intelligence is ingested.

7. Implement IOC enrichment APIs.

Given:

- IP
- Domain
- URL
- File Hash
- Process
- Package
- Dependency

search Supermemory first and return:

- matching CVEs
- IOC reputation
- malware reports
- advisories
- previous evidence
- related incidents

8. Implement semantic retrieval using Supermemory search.

OpenClaw should retrieve only relevant threat intelligence before generating explanations.

The LLM must never perform live web searches.

9. Cache fetched web content locally to avoid unnecessary crawling and API usage.

10. Build a chronological Threat Timeline inside Supermemory.

Every newly ingested CVE or advisory should remain searchable by:

- publication date
- affected package
- CVE
- IOC
- software

11. Expose clean helper APIs:

- update_threat_intelligence()
- enrich_ip(ip)
- enrich_domain(domain)
- enrich_hash(hash)
- enrich_url(url)
- enrich_package(package)
- search_memory(query)
- get_recent_cves()
- get_related_threats(query)

12. Integrate this module with the deterministic Policy Engine.

Before any verdict:

Policy Engine
→ query web_search.py
→ retrieve matching threat intelligence from Supermemory
→ attach structured evidence
→ pass only structured evidence to OpenClaw

13. OpenClaw must act only as an explanation layer.

Every explanation should reference:

- matched CVEs
- IOC reputation
- advisory summaries
- publication dates
- threat intelligence sources
- retrieved evidence from Supermemory

Never allow the LLM to invent security claims.

14. Integrate this module into the Chain of Trust:

Sandbox Report
→ Policy Engine
→ Signature Verification
→ SBOM Generation
→ Dependency Scan
→ Threat Intelligence Lookup (web_search.py)
→ Human Approval
→ Promote to Host

15. Keep the implementation fully modular.

Future providers (VirusTotal, AbuseIPDB, OTX, URLHaus, etc.) should be pluggable without modifying the rest of ClawNet.

Only core/web_search.py should contain:

- Firecrawl integration
- Supermemory SDK integration
- document ingestion
- semantic retrieval
- caching
- threat intelligence normalization
- enrichment logic

Every other module should simply call the helper APIs exposed by web_search.py.