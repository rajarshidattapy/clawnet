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



After implementing the sandbox hardening features, build a complete end-to-end test flow to verify that the entire Docker security pipeline works correctly.

The goal is to demonstrate ClawNet automatically launching a Docker sandbox, monitoring it in real time, analyzing its behavior, and making a promotion decision.

Test Requirements:

1. Create a small intentionally "suspicious" demo repository (inside a temporary test folder) that:
- performs a pip install
- creates child processes
- makes outbound HTTP requests
- reads environment variables
- attempts to access ~/.ssh (or Windows equivalent)
- spawns a shell
- writes temporary files

The repository should be harmless but exercise every telemetry feature.

2. Running:

clawnet --isolation <test_repo>

should automatically:

- create the Docker container
- launch the sandbox
- stream logs live
- start behavioral telemetry
- monitor installation behavior
- monitor process trees
- monitor file access
- monitor network activity
- monitor child processes
- monitor persistence attempts
- monitor sensitive file access

3. Display live terminal updates while the container is running.

Example:

✓ Container Created
✓ Docker Sandbox Started
✓ Installing Dependencies...
✓ Monitoring Installation Scripts...
✓ Collecting Process Tree...
✓ Monitoring Network Connections...
✓ Monitoring Filesystem...
✓ Running Policy Engine...
✓ Threat Intelligence Lookup...
✓ Risk Score Updated...
✓ Awaiting Completion...

4. When execution finishes, automatically generate a complete Behavior Report including:

- processes created
- parent/child tree
- dependencies installed
- installation hooks executed
- files accessed
- sensitive file access attempts
- outbound connections
- DNS lookups
- persistence attempts
- policy violations
- triggered rules
- deterministic risk score
- final verdict

5. If any suspicious behavior is detected:

- display the exact evidence
- show the deterministic score breakdown
- show matching threat intelligence
- explain the verdict using OpenClaw

6. The sandbox should then automatically execute the Chain of Trust:

Behavior Report
→ Policy Engine
→ Signature Verification
→ SBOM Generation
→ Dependency Scan
→ Threat Intelligence Lookup
→ Human Approval
→ Final Decision

7. If the project is SAFE:

display:

✓ Sandbox Passed
✓ Safe to Promote
Approve promotion? (Y/N)

If approved, copy/promote the project to the host workspace.

8. If the project is SUSPICIOUS or CRITICAL:

display:

✗ Promotion Blocked

show the evidence and require explicit approval before any further action.

9. Automatically destroy the Docker container after completion and clean up all temporary resources.

10. Ensure the demonstration is completely automated so that running a single command visibly shows the entire sandbox lifecycle from container creation to cleanup without requiring manual Docker commands.

The implementation should be demo-friendly, producing a clear, real-time visualization of the entire secure execution pipeline.