"""RBAC: roles map to the OBSERVE / EXECUTE / CONTROL tiers, and the caller is audited.

The integration tests drive the real MCP app over HTTP (JSON-RPC `tools/call`), so they
cover the authentication layer, the role lookup and the tool wrapper together.
"""
import json
import time

import jwt
import pytest
from starlette.testclient import TestClient

import clawforge  # noqa: F401  (puts core/ on sys.path)
import policy
from clawforge import mcp_server, rbac

KEY = "k" * 32
REASON = "Kill it: beacons to a flagged IP, and nothing else depends on it."
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


# ── role logic ────────────────────────────────────────────────────────────────

def test_roles_map_to_the_tiers():
    assert [rbac.allowed("viewer", t) for t in (rbac.OBSERVE, rbac.EXECUTE, rbac.CONTROL)] == [True, False, False]
    assert [rbac.allowed("analyst", t) for t in (rbac.OBSERVE, rbac.EXECUTE, rbac.CONTROL)] == [True, True, False]
    assert [rbac.allowed("responder", t) for t in (rbac.OBSERVE, rbac.EXECUTE, rbac.CONTROL)] == [True] * 3
    assert not rbac.allowed(None, rbac.OBSERVE) and not rbac.allowed("root", rbac.OBSERVE)


def test_every_registered_tool_is_in_the_tier_the_approval_gate_uses():
    tiers = mcp_server.TOOL_TIERS
    assert {n for n, t in tiers.items() if t == rbac.CONTROL} == set(mcp_server.CONTROL_TOOLS)
    assert {n for n, t in tiers.items() if t == rbac.EXECUTE} == set(mcp_server.EXECUTE_TOOLS)
    assert len(tiers) == 21


def test_roles_come_from_claims(monkeypatch):
    for v in ("CLAWFORGE_ROLE_CLAIM", "CLAWFORGE_ROLE_MAP", "CLAWFORGE_DEFAULT_ROLE", "CLAWFORGE_SERVICE_ROLE"):
        monkeypatch.delenv(v, raising=False)
    assert rbac.role_from_claims({"roles": ["analyst"]}) == "analyst"
    assert rbac.role_from_claims({"roles": ["viewer", "responder", "analyst"]}) == "responder"   # highest wins
    assert rbac.role_from_claims({"role": "analyst"}) == "analyst"
    assert rbac.role_from_claims({"roles": "viewer analyst"}) == "analyst"       # space-separated string
    assert rbac.role_from_claims({"roles": ["admin"]}) == "viewer"               # unknown -> default, least privilege
    assert rbac.role_from_claims({}) == "viewer"
    monkeypatch.setenv("CLAWFORGE_ROLE_MAP", "soc-lead=responder, soc-intern=viewer,bogus=root")
    assert rbac.role_from_claims({"roles": ["SOC-Lead"]}) == "responder"
    monkeypatch.setenv("CLAWFORGE_ROLE_CLAIM", "realm_access.roles")
    assert rbac.role_from_claims({"realm_access": {"roles": ["analyst"]}, "roles": ["responder"]}) == "analyst"
    monkeypatch.setenv("CLAWFORGE_DEFAULT_ROLE", "analyst")
    assert rbac.role_from_claims({}) == "analyst"
    monkeypatch.setenv("CLAWFORGE_DEFAULT_ROLE", "nonsense")
    assert rbac.role_from_claims({}) == "viewer"


# ── over HTTP ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    mp = pytest.MonkeyPatch()
    mp.setenv("CLAWFORGE_TOKEN", "service-secret")
    mp.setenv("CLAWFORGE_JWT_KEY", KEY)
    mp.setenv("CLAWFORGE_JWT_ISSUER", "https://idp.test")
    mp.setenv("CLAWFORGE_JWT_AUDIENCE", "clawforge")
    mp.delenv("CLAWFORGE_SERVICE_ROLE", raising=False)
    with TestClient(mcp_server.app(), base_url="http://127.0.0.1:8765") as c:      # `with` runs the app's lifespan
        yield c
    mp.undo()


@pytest.fixture()
def log(tmp_path, monkeypatch):
    path = tmp_path / "decisions.jsonl"
    monkeypatch.setattr(policy, "DECISION_LOG", path)
    return path


def _entries(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _jwt(sub, roles):
    return jwt.encode({"sub": sub, "roles": roles, "iss": "https://idp.test", "aud": "clawforge",
                       "exp": time.time() + 60}, KEY, algorithm="HS256")


def _call(client, token, tool, **arguments):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments}}
    r = client.post("/mcp", headers={**HEADERS, "Authorization": f"Bearer {token}"}, json=body)
    assert r.status_code == 200, r.text
    result = r.json()["result"]
    return result.get("structuredContent") or json.loads(result["content"][0]["text"])


def test_viewer_may_observe_but_not_execute_or_control(client, log):
    token = _jwt("vera", ["viewer"])
    assert "decisions" in _call(client, token, "recent_decisions", limit=1)
    for tool, args in (("sandbox_run_code", {"code": "print(1)"}),
                       ("kill_process", {"pid": 4242, "reason": REASON})):
        out = _call(client, token, tool, **args)
        assert out["refused"] == "rbac" and "viewer" in out["detail"]
    denied = [e for e in _entries(log) if e["kind"] == "rbac_denied"]
    assert [(e["tool"], e["tier"]) for e in denied] == [("sandbox_run_code", "execute"),
                                                        ("kill_process", "control")]
    assert denied[0]["caller"] == {"sub": "vera", "role": "viewer", "auth": "jwt"}


def test_analyst_may_execute_but_not_control(client, log):
    token = _jwt("alan", ["analyst"])
    out = _call(client, token, "sandbox_run_code", code="print(1)", language="cobol")   # allowed through RBAC
    assert out.get("refused") != "rbac"
    assert _call(client, token, "close_port", port=8080, reason=REASON)["refused"] == "rbac"


def test_responder_reaches_control_tools_and_the_caller_is_audited(client, log):
    token = _jwt("rita", ["responder"])
    # A bad PID passes RBAC and is stopped by the schema guardrail, so nothing on this machine is touched.
    out = _call(client, token, "kill_process", pid=0, reason=REASON)
    assert out["refused"] == "schema"
    refusal = [e for e in _entries(log) if e["kind"] == "action_refused"][-1]
    assert refusal["caller"] == {"sub": "rita", "role": "responder", "auth": "jwt"}


def test_the_service_token_is_the_responder_role(client, log):
    out = _call(client, "service-secret", "kill_process", pid=0, reason=REASON)
    assert out["refused"] == "schema"                                    # got past RBAC
    assert [e for e in _entries(log) if e["kind"] == "action_refused"][-1]["caller"] == \
        {"sub": "service", "role": "responder", "auth": "static-token"}


def test_service_role_can_be_lowered(client, log, monkeypatch):
    monkeypatch.setenv("CLAWFORGE_SERVICE_ROLE", "viewer")
    assert _call(client, "service-secret", "kill_process", pid=4242, reason=REASON)["refused"] == "rbac"
    assert _call(client, "service-secret", "recent_decisions", limit=1)["decisions"] is not None


def test_unauthenticated_calls_never_reach_a_tool(client, log):
    r = client.post("/mcp", headers=HEADERS, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401
    assert mcp_server._principal() is None       # outside a request there is no caller, so the wrapper denies


def test_direct_log_entries_carry_the_caller_only_inside_a_request(log):
    policy.log_decision("probe")
    token = policy.set_caller({"sub": "x", "role": "viewer", "auth": "jwt"})
    try:
        policy.log_decision("probe")
    finally:
        policy.reset_caller(token)
    policy.log_decision("probe")
    assert ["caller" in e for e in _entries(log)] == [False, True, False]
