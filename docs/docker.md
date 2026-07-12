Implement a dedicated Sandbox Hardening & Behavioral Telemetry module to make ClawNet's Docker sandbox a secure execution environment instead of just an isolated container.

All sandbox security, telemetry, and execution monitoring logic should live inside the existing sandbox-related modules (sandbox.py, isolation.py, container_agent.py) and remain modular.

Requirements:

1. Behavioral Telemetry — Expand monitoring beyond network connections to continuously collect process trees, parent/child processes, executed commands, spawned shells, file access, file modifications, registry changes (Windows), startup persistence attempts, environment variable access, and installation behavior.

2. Installation Monitoring — Monitor every package installation command (pip, npm, cargo, go, pnpm, yarn, apt, choco, winget, etc.), record every dependency installed, and feed the results into the Policy Engine before allowing execution.

3. Dependency Execution Tracking — Detect install-time code execution (postinstall scripts, setup.py, install hooks, PowerShell, shell scripts, native compilation, etc.) and treat these as first-class security events.

4. Filesystem Activity Monitoring — Detect access to sensitive paths such as SSH keys, browser profiles, credentials, API keys, environment files, Windows user directories, and other protected locations.

5. Process Lineage Tracking — Build complete process ancestry graphs (Parent → Child → Grandchild) to identify suspicious execution chains instead of evaluating processes independently.

6. Sandbox Hardening — Strengthen the Docker sandbox using rootless containers where possible, dropped Linux capabilities, read-only root filesystem where appropriate, seccomp profiles, AppArmor (where supported), no-new-privileges, resource limits (CPU, RAM, PIDs), isolated networking, temporary writable volumes only, and automatic container cleanup.

7. Secret Isolation — Prevent sandboxed applications from accessing host secrets, SSH keys, browser cookies, API tokens, Git credentials, Docker socket, mounted drives, or host environment variables unless explicitly approved.

8. Host Protection Policy — Ensure no sandboxed process can directly modify the host filesystem, registry, startup folders, scheduled tasks, services, or user configuration.

9. Malware Containment — Treat Docker as only one security layer and implement additional safeguards so malicious code cannot escape the sandbox or interact with the host beyond explicitly allowed interfaces.

10. Sandbox Evidence Collection — Generate a complete behavioral report containing executed processes, accessed files, installation events, network activity, persistence attempts, privilege escalation attempts, and policy violations.

11. Risk Integration — Feed all collected behavioral telemetry into the deterministic Policy Engine so verdicts are based on observed behavior rather than network activity alone.

12. Promotion Gate — A project can only be promoted from the sandbox to the host after successfully passing the complete Chain of Trust:
Behavior Report → Policy Engine → Signature Verification → SBOM → Dependency Scan → Threat Intelligence Lookup → Human Approval → Promote to Host.

13. Keep the implementation modular so additional sandbox backends (gVisor, Firecracker, Kata Containers, Windows Sandbox, etc.) can be added in the future without changing the rest of ClawNet.