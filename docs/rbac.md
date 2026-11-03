# RBAC and authentication

Part 1 is how access control is usually built for agents and tool servers. Part 2 is how ClawNet / ClawForge does it: who the caller is, what role they get, what that role may call, and how it is audited.

---

## Part 1: Access control for agents, in general

### Authentication and authorization are different questions

| | Question | Typical mechanism |
|---|---|---|
| **Authentication** (authn) | *Who* is calling? | API key, bearer token, OAuth2 / OIDC access token (JWT), mTLS |
| **Authorization** (authz) | *What may they do?* | Roles (RBAC), attributes (ABAC), per-resource ACLs, scopes |
| **Audit** | *What did they do?* | Append-only log with the caller's identity on every entry |

### Why agents need it

An agent server exposes tools: read data, run code, change the system. Without access control, whoever can reach the server can call every tool. With an agent in the loop there are two more reasons:

- **The agent is not the user.** A model acts on behalf of someone. The server needs to know which someone, so a junior analyst's session cannot be used to do what only a lead may do.
- **The agent can be manipulated.** Prompt injection can steer a model into calling a tool it should not. Access control enforced in the server holds regardless of what the model was talked into.

### Common building blocks

1. **Static service tokens.** One shared secret between two components. Simple, fine for machine-to-machine on a single host, but it identifies *a service*, not a person, and it cannot be scoped or expire on its own.
2. **OAuth2 / OIDC access tokens (JWTs).** Issued by an identity provider (Auth0, Okta, Keycloak, Entra ID). The server verifies the signature against the provider's public keys (JWKS), then checks expiry (`exp`), issuer (`iss`) and audience (`aud`). Claims carry the user's identity (`sub`) and often their roles or scopes.
3. **RBAC (role-based access control).** Users get *roles*, roles get *permissions*. Easy to reason about and to audit. Roles are coarse by design.
4. **Scopes.** OAuth's version of a permission string (`tools:execute`). Often used alongside roles.
5. **Least privilege.** Anything unrecognised gets the lowest access, not the highest.
6. **Tier the tools by risk.** Read-only, sandboxed side effects, and host-changing actions are different risk classes. Roles are easiest to define against those tiers.
7. **Human approval is a separate control.** RBAC says *may this caller attempt it*. Approval says *does a human agree, now, for this instance*. High-risk tools should need both.
8. **Audit with identity.** A log entry that says "process killed" is much less useful than one that says who asked.

### Where to enforce it

- At the **server**, in the code path that runs the tool. Not in the system prompt, and not only in the UI.
- Derive the access tier from the **same metadata** the rest of the system uses, so two definitions of "dangerous" cannot drift apart.
- **Fail closed.** No authenticated caller means no tool call.

---

## Part 2: RBAC in ClawNet / ClawForge

### The picture

```
 TrueForge connector ──static token──┐
                                      ▼
 SOC user / service ──JWT (OAuth)──►  TokenAuth  (ASGI middleware)   clawforge/mcp_server.py
                                      │  verifies the credential
                                      │  decides the caller's ROLE        clawforge/rbac.py
                                      ▼
                              principal {sub, role, auth}
                                      │
                                      ▼
                              tool() wrapper  ── role allowed for this tool's TIER?
                                      │              no  → {"refused": "rbac"} + log "rbac_denied"
                                      │              yes → set the caller for the audit log
                                      ▼
                    the tool runs (control tools still pause for a human)
                                      ▼
                  ~/.clawnet/decisions.jsonl   every entry carries "caller"
```

### 1. Authentication

`TokenAuth` in `clawforge/mcp_server.py` sits in front of the MCP app. A request must carry `Authorization: Bearer ...` and it is accepted if it is either:

- **The static service token.** This is what the registered TrueForge connector sends. It comes from `CLAWFORGE_TOKEN`, or a random one persisted at `~/.clawnet/clawforge_token`.
- **A valid OAuth/JWT access token**, when JWT auth is configured. `JwtVerifier` checks the signature (against `CLAWFORGE_JWKS_URL`, or a fixed `CLAWFORGE_JWT_KEY`), and requires `exp`, `iss` and `aud`. The issuer and audience must match `CLAWFORGE_JWT_ISSUER` and `CLAWFORGE_JWT_AUDIENCE`, so a token minted for another service is refused.

Anything else gets `401` with a `WWW-Authenticate` header. Set `CLAWFORGE_JWT_ONLY=1` to refuse the static token (the TrueForge connector would then need a JWT).

A successful check produces a **principal**: `{"sub", "auth", "role", ...}`, stored on the request.

### 2. Roles

Three roles, each including the tiers of the one before:

| Role | OBSERVE (read-only) | EXECUTE (sandbox) | CONTROL (changes the host) |
|---|---|---|---|
| `viewer` | yes | no | no |
| `analyst` | yes | yes | no |
| `responder` | yes | yes | yes, but each call still waits for a human |

Roles are defined in `clawforge/rbac.py` (`ROLES`).

### 3. The tiers

The tiers are the ones the server already used for approval. Each tool's tier comes from its MCP annotations:

| Tier | Annotation | Tools |
|---|---|---|
| OBSERVE | `readOnlyHint` | `system_status`, `list_connections`, `suspicious_processes`, `inspect_process`, `who_is_listening`, `explain_pid`, `lookup_evidence`, `threat_intel`, `recent_decisions`, `preview_action`, `list_sandbox_runs`, `sandbox_report` |
| EXECUTE | neither read-only nor destructive | `sandbox_run_code`, `sandbox_run_path`, `sandbox_clone` |
| CONTROL | `destructiveHint` | `kill_process`, `suspend_process`, `block_ip`, `quarantine_file`, `close_port`, `promote_sandbox_run` |

Because the annotations are the single source, a tool cannot be "needs approval" in one place and "any role may call it" in another. A test checks that the registered tiers match `CONTROL_TOOLS` and `EXECUTE_TOOLS`.

### 4. How a caller gets a role

| Caller | Role |
|---|---|
| Static service token (TrueForge) | `CLAWFORGE_SERVICE_ROLE`, default **`responder`**. The agent needs the control tools, and every one of them still waits for a human |
| JWT | the **highest** role found in its roles claim |
| JWT with no recognised role | `CLAWFORGE_DEFAULT_ROLE`, default **`viewer`** (least privilege) |

Reading roles from a JWT:

- The claim is `roles` by default, and `role` is also checked. Change it with `CLAWFORGE_ROLE_CLAIM`. Dotted paths work, e.g. `realm_access.roles` for Keycloak.
- The value can be a list (`["analyst"]`) or a space/comma separated string (`"viewer analyst"`).
- `CLAWFORGE_ROLE_MAP` renames your identity provider's roles to ours: `CLAWFORGE_ROLE_MAP=soc-lead=responder,soc-analyst=analyst,soc-intern=viewer`. Matching is case-insensitive. Entries that map to a role that does not exist are ignored.
- If a token has several roles, the highest wins.

### 5. Enforcement

`tool()` in `clawforge/mcp_server.py` replaces `@mcp.tool` for all 21 tools. For each call it:

1. Reads the authenticated principal from the request.
2. Checks that the principal's role allows the tool's tier.
3. If not, returns `{"ok": false, "refused": "rbac", "tool": ..., "detail": "role 'viewer' may not call control tools (kill_process)"}` and writes an `rbac_denied` entry. A call with no authenticated caller is refused the same way (fail closed).
4. If allowed, sets the caller for the duration of the call, runs the tool, and clears it.

Enforcement is in the server's tool path, so it holds whichever client calls the server.

**RBAC is one layer of several.** For a control tool, a call passes through all of these, and any can stop it:

```
RBAC (may this role call this tier?)
  → human approval in TrueForge / the harness
  → JSON Schema validation of the arguments       (docs/guardrails.md)
  → ClawNet policy refusal (protected processes, private IPs, System32, ...)
```

### 6. Audit

`core/policy.py` keeps the current caller in a context variable. `log_decision()` adds it to every entry made while that request is being served:

```json
{"ts": "2026-11-03T10:15:00", "kind": "action_refused", "action": "kill_process",
 "guardrail": "schema", "caller": {"sub": "rita", "role": "responder", "auth": "jwt"}}
```

- This covers verdicts, executed actions, schema refusals and RBAC denials.
- `rbac_denied` entries name the tool, its tier and the caller.
- For the static token the caller is `{"sub": "service", "role": "responder", "auth": "static-token"}`.
- Entries made outside a request (the local CLI, background monitors) have no `caller` field, as before.

### Configuration

All optional, in `.env`:

| Variable | Default | Meaning |
|---|---|---|
| `CLAWFORGE_TOKEN` | auto-generated | static service token |
| `CLAWFORGE_JWKS_URL` / `CLAWFORGE_JWT_KEY` | unset | turns JWT auth on (key source) |
| `CLAWFORGE_JWT_ISSUER`, `CLAWFORGE_JWT_AUDIENCE` | required with JWT | must match the token |
| `CLAWFORGE_JWT_ALGORITHMS` | `RS256,ES256` (`HS256` for a shared secret) | allowed signing algorithms |
| `CLAWFORGE_JWT_ONLY` | off | refuse the static token |
| `CLAWFORGE_SERVICE_ROLE` | `responder` | role of the static token |
| `CLAWFORGE_ROLE_CLAIM` | `roles` | where to read roles in the JWT |
| `CLAWFORGE_ROLE_MAP` | none | rename identity-provider roles to `viewer` / `analyst` / `responder` |
| `CLAWFORGE_DEFAULT_ROLE` | `viewer` | role for a JWT with no recognised role |

The server prints the active RBAC settings when it starts.

### Example

A SOC setup with an identity provider that issues `soc-lead`, `soc-analyst` and `soc-intern`:

```
CLAWFORGE_JWKS_URL=https://idp.example.com/.well-known/jwks.json
CLAWFORGE_JWT_ISSUER=https://idp.example.com/
CLAWFORGE_JWT_AUDIENCE=clawforge
CLAWFORGE_ROLE_MAP=soc-lead=responder,soc-analyst=analyst,soc-intern=viewer
```

| Caller | Can read status | Can run code in the sandbox | Can propose a kill |
|---|---|---|---|
| `soc-intern` | yes | no | no |
| `soc-analyst` | yes | yes | no |
| `soc-lead` | yes | yes | yes, after human approval |
| TrueForge connector (static token) | yes | yes | yes, after human approval |

### Limits

- **Tiers, not targets.** A role says which *class* of tool a caller may use. It does not restrict *which* process, IP or file. That judgment stays with the policy layer.
- **Three fixed roles.** There is no custom role editor. Add a role by editing `ROLES` in `clawforge/rbac.py`.
- **Tools are not hidden.** A viewer still sees all 21 tools in the tool list and is refused when it calls a restricted one.
- **Default service role is `responder`.** That keeps the TrueForge agent working. If you do not want the agent to have the control tools at all, set `CLAWFORGE_SERVICE_ROLE=analyst`.
- **One identity per agent.** The agent itself runs as the connector's service identity, not as the human who started the session. Per-human attribution works for direct JWT callers; for the TrueForge agent the human approver is recorded by the harness (`approved_by`), not as the MCP caller.
- **The `harness` terminal UI is local.** It talks to TrueForge and to the local policy code, not through the MCP server's role checks.

### Where it lives

| Concern | File |
|---|---|
| Roles, claim and role-map parsing, tier from annotations | `clawforge/rbac.py` |
| Authentication, `tool()` wrapper, caller lookup | `clawforge/mcp_server.py` |
| Caller in the decision log | `core/policy.py` (`set_caller`, `log_decision`) |
| Tests (over real HTTP) | `tests/test_rbac.py` |
