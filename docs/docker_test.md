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