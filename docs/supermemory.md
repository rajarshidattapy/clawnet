Implement a dedicated Evidence-Based Memory Engine to replace simple "AI memory" with forensic security memory.

All persistent memory logic should live inside core/memory.py and remain the single source of truth for historical evidence. The memory should store structured security evidence—not AI opinions.

Requirements:

1. Replace memory entries like "node.exe was suspicious" with evidence-backed records containing:
- SHA256 hash
- executable path
- process name
- parent process
- process tree
- file metadata
- destination IPs
- ASN
- DNS queries
- ports
- network behavior
- filesystem activity
- registry/startup persistence attempts
- installed dependencies
- digital signature status
- triggered policy rules
- deterministic risk score
- final verdict
- timestamp

2. Store every sandbox execution as a complete forensic snapshot instead of only the final verdict.

3. Every memory entry should maintain a complete timeline of observations so repeated executions of the same binary or repository build historical context instead of overwriting previous results.

4. Implement evidence lookup APIs such as:
- lookup_sha256()
- lookup_process()
- lookup_ip()
- lookup_domain()
- lookup_repository()
- lookup_dependency()
- lookup_behavior()

5. Before analyzing any new process or repository, automatically search memory for matching hashes, IPs, domains, process names, behaviors, or similar execution patterns.

6. If a previous match exists, enrich the current analysis with historical evidence including previous verdicts, timestamps, behavior reports, and policy decisions.

7. Never store LLM-generated opinions as memory. Memory should only contain deterministic evidence collected from telemetry, the policy engine, sandbox reports, and threat intelligence.

8. OpenClaw should only query memory to retrieve evidence and historical context before generating explanations—it must never directly write arbitrary observations into memory.

9. Build behavior fingerprinting so similar executions can be matched even if filenames change. Compare process trees, network behavior, accessed files, child processes, installation behavior, and persistence attempts.

10. Every AI explanation should reference the retrieved evidence from memory instead of saying "this looks suspicious." For example:
- Previously observed 3 times
- First seen: <timestamp>
- SHA256 matched
- Same ASN contacted
- Same process tree
- Previous Verdict: CRITICAL

11. Keep the implementation modular so memory acts as a reusable evidence database for the Policy Engine, Threat Intelligence Agent, and OpenClaw without duplicating storage logic.