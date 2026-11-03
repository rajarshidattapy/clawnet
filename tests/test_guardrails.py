"""Output guardrails: secret/PII redaction and the control-action schema."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
import guardrails as g  # noqa: E402

REASON = "Kill it: beacons to a flagged IP, and nothing else depends on it."


def test_secrets_are_redacted():
    text = ("openai sk-proj-abcdefghijklmnopqrstuvwxyz123456, google AIzaSyA1234567890123456789012345678901, "
            "aws AKIAABCDEFGHIJKLMNOP, gh ghp_abcdefghijklmnopqrstuvwxyz0123456789, "
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk, "
            "PASSWORD=hunter2hunter, url https://user:pw12345@host/x")
    out = g.redact(text)
    for leaked in ("abcdefghijklmnop", "AIzaSy", "AKIAABC", "ghp_", "eyJhbGci", "hunter2", "pw12345"):
        assert leaked not in out
    assert out.count("[REDACTED:") == 7
    assert "PASSWORD=[REDACTED:secret]" in out and "https://[REDACTED:password-in-url]@host" in out


def test_pii_is_redacted_and_security_evidence_is_not():
    out = g.redact("mail bob@corp.com tel +1 415-555-0132 ssn 123-45-6789 card 4111 1111 1111 1111")
    assert out == ("mail [REDACTED:email] tel [REDACTED:phone] ssn [REDACTED:ssn] "
                   "card [REDACTED:credit-card]")
    evidence = ("pid 4242 port 443 ip 203.0.113.9 "
                "sha 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 "
                r"path C:\Users\a\AppData\Local\Temp\x.exe 2026-11-03T10:15:00 1234 5678 9012 3456")
    assert g.redact(evidence) == evidence        # not a Luhn-valid card, not a phone number


def test_redaction_reports_what_it_found_and_is_idempotent():
    out, kinds = g.redact_report("a@b.co and sk-ant-abcdefghijklmnopqrstuvwxyz")
    assert sorted(kinds) == ["api-key", "email"] and g.redact(out) == out
    assert g.redact("") == "" and g.redact_report("clean text")[1] == []


def test_stream_redactor_catches_a_secret_split_across_chunks():
    r = g.StreamRedactor()
    chunks = ["the key is sk-proj-abcdefgh", "ijklmnopqrstuvwxyz123456 and mail bo", "b@corp.com. done"]
    out = "".join(r.feed(c) for c in chunks) + r.flush()
    assert out == "the key is [REDACTED:api-key] and mail [REDACTED:email]. done"


def test_well_formed_actions_pass():
    assert g.validate_action("kill_process", {"pid": 4242, "reason": REASON}) == []
    assert g.validate_action("block_ip", {"ip": "8.8.8.8", "reason": REASON}) == []
    assert g.validate_action("close_port", {"port": 8080, "reason": REASON}) == []
    assert g.validate_action("promote_sandbox_run", {"run_id": "run-01_a", "reason": REASON}) == []
    assert g.validate_action("quarantine_file",
                             {"path": r"C:\Users\a\Downloads\x.exe", "reason": REASON}) == []


def test_malformed_actions_are_rejected():
    bad = [
        ("kill_process", {"pid": True, "reason": REASON}),                    # bool is not an int
        ("kill_process", {"pid": "4242", "reason": REASON}),                  # wrong type
        ("kill_process", {"pid": 0, "reason": REASON}),                       # not a real PID
        ("kill_process", {"pid": 4242}),                                      # no reason
        ("kill_process", {"pid": 4242, "reason": "because"}),                 # reason too thin
        ("kill_process", {"pid": 4242, "reason": REASON, "force": True}),     # extra argument
        ("block_ip", {"ip": "evil.example.com", "reason": REASON}),           # a hostname, not an IP
        ("block_ip", {"ip": "8.8.8.8/8", "reason": REASON}),                  # a range, not an IP
        ("close_port", {"port": 70000, "reason": REASON}),
        ("quarantine_file", {"path": r"..\x.exe", "reason": REASON}),         # relative
        ("quarantine_file", {"path": r"C:\Users\a\..\Windows\x.dll", "reason": REASON}),   # traversal
        ("quarantine_file", {"path": r"C:\Users\*.exe", "reason": REASON}),   # wildcard
        ("promote_sandbox_run", {"run_id": "../../etc", "reason": REASON}),
        ("format_disk", {"reason": REASON}),                                  # not a known action
    ]
    for action, args in bad:
        assert g.validate_action(action, args), (action, args)
    assert g.validate_action("kill_process", "not an object")


def test_capabilities_refuse_a_bad_proposal_before_running_it(monkeypatch):
    from clawforge import capabilities as cap

    class Boom:
        def kill_process(self, pid):
            raise AssertionError("must not run")

    monkeypatch.setattr(cap, "_monitor", lambda: Boom())
    out = cap.kill_process(4242, "no")
    assert out["ok"] is False and out["refused"] == "schema" and out["errors"]
