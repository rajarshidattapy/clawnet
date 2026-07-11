"""Deterministic regression suite for the policy engine and OpenClaw.

Runs fully offline against the recorded cassette (tests/recordings/openclaw.json)
— no API key, no network, $0. Run with pytest, or just: python tests/test_policy.py
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

import policy
import replay
from openclaw import OpenClaw


def test_policy_rules_and_guardrails():
    """The rule engine, guardrails and injection firewall (policy.py self-check)."""
    policy.demo()


def test_deterministic_replay_ships():
    """Replay every recorded flow through every hostile world — offline, $0.

    Fails CI if a change makes verdicts non-deterministic, lets prompt injection
    move a verdict, recommends an action a guardrail would refuse, or lets an
    explanation contradict the verdict it explains.
    """
    if not replay.CASSETTE_PATH.exists():
        replay.record_fixtures()
    os.environ["CLAWNET_REPLAY"] = "replay"
    report = replay.score(replay.FIXTURES, explain=replay._cassette_explain)
    assert report["ship"], report["failures"]


def test_unrecorded_call_flags_never_fabricates():
    """The simulator refuses unknown inputs rather than inventing a result."""
    os.environ["CLAWNET_REPLAY"] = "replay"
    unseen = policy.Evidence(pid=1, process="never-recorded.exe", remote="9.9.9.9",
                             rport=4444, foreign=True)
    try:
        replay._cassette_explain(unseen, policy.evaluate(unseen))
        raise AssertionError("expected NotRecorded — the simulator must not fabricate")
    except replay.NotRecorded:
        pass


def test_llm_cannot_change_the_verdict():
    """A hostile/lying model must not move level or action — policy decides both."""
    os.environ["CLAWNET_REPLAY"] = "off"
    ev = replay.FIXTURES[0]                  # temp-path binary, port 4444, RU
    verdict = policy.evaluate(ev)
    assert verdict.level == "CRITICAL"

    oc = OpenClaw.__new__(OpenClaw)           # no client, no thread, no key
    oc._cache, oc._memory, oc._ok = {}, None, False
    import threading, queue
    oc._lock, oc._q = threading.Lock(), queue.Queue()

    oc.request(("k",), ev, verdict)
    a = oc.get(("k",))
    assert a.level == "CRITICAL"              # from the policy engine
    assert a.action == "kill_and_block"
    assert a.score == verdict.score

    # a model that calls a CRITICAL connection "safe" is caught and discarded
    assert policy.contradicts(replay.HOSTILE_RESPONSES[0], "CRITICAL")
    assert policy.contradicts("This connection is completely safe.", "CRITICAL")
    assert not policy.contradicts("Untrusted binary beaconing to Russia.", "CRITICAL")


def test_high_risk_actions_need_approval():
    for action in ("kill_process", "block_ip", "kill_and_block", "quarantine_file"):
        assert policy.needs_approval(action)
    for action in ("none", "monitor"):
        assert not policy.needs_approval(action)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
    print("\nall deterministic checks passed (offline, $0)")
