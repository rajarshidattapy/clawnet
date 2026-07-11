Implement the following security features in ClawNet to make the AI explain deterministic security decisions instead of making them.

1. Deterministic Policy Engine — Replace LLM-based risk scoring with a rule engine that assigns scores from explicit signals (unsigned binaries, destination reputation, process ancestry, sensitive file access, foreign IPs, dangerous ports, etc.) so every verdict is reproducible.

2. Evidence Collection Layer — Before any AI analysis, collect structured evidence (process tree, executable path, file hash, network connections, DNS, parent PID, accessed files, timestamps) for every suspicious event.

3. Explainability Engine — OpenClaw should never decide SAFE/SUSPICIOUS/CRITICAL; it should only explain the policy engine's verdict in natural language using the collected evidence.

4. Human Approval Gate — High-risk remediation actions (kill process, block IP, quarantine file, firewall changes) must always require explicit user approval before execution.

5. Safe Action Guardrails — Prevent the AI from executing dangerous or nonsensical actions (e.g., killing explorer.exe, deleting system files); enforce allowlists/denylists and system-process protection.

6. Prompt Injection Firewall — Never send repository files (README, source code, prompts, comments, markdown, etc.) directly to the LLM. Strip instructions and only pass structured security evidence to prevent prompt injection.

7. Structured LLM Context — The LLM should receive only sanitized JSON describing evidence and policy results, never raw repository text or user-controlled instructions.

8. Repository Reputation Memory — Store previous analyses (hashes, domains contacted, behaviors, verdicts, approvals) so repeated repositories or behaviors are recognized without relying solely on fresh LLM reasoning.

9. Deterministic Evaluation Suite — Integrate Volo to record and replay OpenClaw decision flows, enabling deterministic offline regression tests for the policy engine and AI explanations in CI.

10. Confidence & Evidence Display — Every verdict should include the triggered rules, evidence summary, calculated score, and confidence so users understand exactly why a decision was made.

11. Immutable Decision Log — Persist every policy decision, evidence snapshot, user approval, and executed action for auditing and future replay.

12. AI as Security Analyst Only — Redesign OpenClaw's role to act as an analyst that interprets evidence, summarizes threats, and recommends actions; all enforcement decisions must originate from the deterministic policy engine.
