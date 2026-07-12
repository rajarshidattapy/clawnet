"""ClawNet evidence memory — forensic security memory, not "AI memory".

Single source of truth for historical evidence. Stores structured, deterministic
evidence (hashes, process trees, network behavior, policy verdicts) — never LLM
opinions. Every observation is appended, so repeated executions of the same
binary or repo build a timeline instead of overwriting each other.

Backends (docs/docs_supermemorylocal.md):
  · Source of truth: append-only JSONL at ~/.clawnet/evidence.jsonl. Deterministic
    lookups and behavior fingerprinting run against this, always offline.
  · Optional mirror: the self-hosted Supermemory server for semantic search.
        bunx supermemory local          # prints an sm_... API key
        export SUPERMEMORY_API_KEY=sm_...
        export SUPERMEMORY_API_URL=http://localhost:6767   # default
    If the server is down or no key is set, ClawNet still works — the JSONL store
    answers every query.

Modularity: the Policy Engine, sandbox, and the ClawNet agent all import this one
store. The agent only ever *queries* it (it must never write observations).
"""
import json
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

_DIR             = Path.home() / ".clawnet"
_EVIDENCE_PATH   = _DIR / "evidence.jsonl"
_LEGACY_JSON     = _DIR / "memory.json"          # migrated in on first load
_MAX_RECORDS     = 10000

# Verdict severity, unified across the network monitor (CRITICAL) and the
# sandbox (DANGEROUS). Higher = worse.
_SEVERITY = {"SAFE": 0, "?": 0, "SUSPICIOUS": 1, "CRITICAL": 2, "DANGEROUS": 2}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _worst(verdicts: list) -> str:
    return max((v for v in verdicts if v), key=lambda v: _SEVERITY.get(v, 0), default="")

# ── record builders ───────────────────────────────────────────────────────────


def behavior_fingerprint(rec: dict) -> str:
    """A filename-independent hash of *behavior*, so the same malware matches even
    if its file was renamed. Built from process-tree shapes, network behavior,
    accessed-file categories, child process names, install managers, persistence.
    """
    import hashlib
    trees   = sorted({" > ".join(t.split(" > ")) for t in (rec.get("process_tree") or [])})
    signals = sorted(rec.get("network_behavior") or [])
    cats    = sorted({f.get("category", "") for f in (rec.get("file_access") or []) if f.get("category")})
    childs  = sorted({p.get("comm", "") for p in (rec.get("processes") or []) if p.get("comm")})
    mgrs    = sorted({i.get("manager", "") for i in (rec.get("dependencies") or []) if isinstance(i, dict)})
    persist = sorted({Path(p).name for p in (rec.get("persistence") or [])})
    blob    = json.dumps([trees, signals, cats, childs, mgrs, persist], sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:32]


def make_evidence(**fields) -> dict:
    """Build one forensic evidence record. Only deterministic fields — no opinions.

    Recognised fields mirror the evidence checklist: sha256, exe, process, parent,
    process_tree, file_metadata, remote_ips, asn, dns, ports, network_behavior,
    file_access, persistence, dependencies, signature, policy_rules, risk_score,
    verdict, repository, kind, source.
    """
    rec = {
        "ts":               fields.get("ts") or _now_iso(),
        "kind":             fields.get("kind", "network"),      # network | sandbox
        "source":           fields.get("source", "policy-engine"),
        "sha256":           fields.get("sha256", ""),
        "exe":              fields.get("exe", ""),
        "process":          fields.get("process", ""),
        "parent":           fields.get("parent", ""),
        "process_tree":     list(fields.get("process_tree", []) or []),
        "processes":        list(fields.get("processes", []) or []),
        "file_metadata":    dict(fields.get("file_metadata", {}) or {}),
        "remote_ips":       list(fields.get("remote_ips", []) or []),
        "asn":              list(fields.get("asn", []) or []),
        "dns":              list(fields.get("dns", []) or []),
        "ports":            list(fields.get("ports", []) or []),
        "network_behavior": list(fields.get("network_behavior", []) or []),
        "file_access":      list(fields.get("file_access", []) or []),
        "persistence":      list(fields.get("persistence", []) or []),
        "dependencies":     list(fields.get("dependencies", []) or []),
        "signature":        dict(fields.get("signature", {}) or {}),
        "policy_rules":     list(fields.get("policy_rules", []) or []),
        "risk_score":       int(fields.get("risk_score", 0) or 0),
        "verdict":          fields.get("verdict", "?"),
        "repository":       fields.get("repository", ""),
    }
    rec["fingerprint"] = fields.get("fingerprint") or behavior_fingerprint(rec)
    return rec


def make_event(level: str, reason: str, action: str, process: str, remote_ip: str,
               port: int = 0, exe: str = "", decision: str = "") -> dict:
    """Legacy compact event — kept so existing callers keep working. Projected
    into a full evidence record on store."""
    return {
        "ts": _now_iso(), "level": level, "reason": reason, "action": action,
        "process": process, "remote_ip": remote_ip, "port": port, "exe": exe,
        "decision": decision,
    }


def _event_to_evidence(ev: dict) -> dict:
    return make_evidence(
        ts=ev.get("ts"), kind="network", source="policy-engine",
        process=ev.get("process", ""), exe=ev.get("exe", ""),
        remote_ips=[ev["remote_ip"]] if ev.get("remote_ip") else [],
        ports=[ev["port"]] if ev.get("port") else [],
        verdict=ev.get("level", "?"), risk_score=ev.get("score", 0),
        network_behavior=[ev["reason"]] if ev.get("reason") else [],
        # carry a decision (user approval) so prior_decision_lookup still works
        policy_rules=[f"decision:{ev['decision']}"] if ev.get("decision") else [],
    )


def evidence_summary(ctx: dict) -> list[str]:
    """Human-readable historical evidence lines for an AI explanation to cite —
    'Previously observed 3 times', 'SHA256 matched', 'Same ASN', etc. (req 10)."""
    if not ctx or not ctx.get("seen_count"):
        return []
    out = [f"Previously observed {ctx['seen_count']} time(s)"]
    if ctx.get("first_seen"):
        out.append(f"First seen: {ctx['first_seen']}")
    if ctx.get("sha256_match"):
        out.append("SHA256 matched a prior run")
    if ctx.get("fingerprint_match"):
        out.append("Same behavioral fingerprint (renamed but identical behavior)")
    if ctx.get("same_asn"):
        out.append(f"Same ASN contacted: {', '.join(ctx['same_asn'][:3])}")
    if ctx.get("matched_ips"):
        out.append(f"Same IP(s) contacted: {', '.join(ctx['matched_ips'][:3])}")
    if ctx.get("process_trees"):
        out.append("Same process tree observed before")
    if ctx.get("worst_verdict"):
        out.append(f"Worst prior verdict: {ctx['worst_verdict']}")
    return out

# ── the store ─────────────────────────────────────────────────────────────────


class SuperMemory:
    """Deterministic, append-only forensic evidence store."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path   = path or _EVIDENCE_PATH
        self._recs: deque = deque(maxlen=_MAX_RECORDS)
        self._lock   = threading.Lock()

        self._load()

    @property
    def backend(self) -> str:
        return "jsonl"

    # ── write (deterministic sources only) ─────────────────────────────────────

    def store_evidence(self, record: dict) -> None:
        """Append one forensic record. Never overwrites — builds the timeline."""
        if "fingerprint" not in record:
            record["fingerprint"] = behavior_fingerprint(record)
        with self._lock:
            self._recs.append(record)
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
            except Exception:
                pass
    def store_event(self, event: dict) -> None:
        """Legacy entry point — projected into a full evidence record."""
        self.store_evidence(_event_to_evidence(event))

    # ── lookups (req 4) ────────────────────────────────────────────────────────

    def _scan(self, predicate, limit: int, days: int = 0) -> list[dict]:
        cutoff = ((datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")) if days else ""
        out: list[dict] = []
        with self._lock:
            for rec in reversed(self._recs):          # most-recent first
                if cutoff and rec.get("ts", "") < cutoff:
                    continue
                if predicate(rec):
                    out.append(rec)
                    if len(out) >= limit:
                        break
        return out

    def lookup_sha256(self, sha256: str, limit: int = 20) -> list[dict]:
        s = (sha256 or "").lower()
        return self._scan(lambda r: s and r.get("sha256", "").lower() == s, limit) if s else []

    def lookup_process(self, name: str, limit: int = 20) -> list[dict]:
        n = (name or "").lower()
        return self._scan(
            lambda r: n and (n in r.get("process", "").lower()
                             or any(n in p.get("comm", "").lower() for p in r.get("processes", []))),
            limit) if n else []

    def lookup_ip(self, ip: str, limit: int = 20) -> list[dict]:
        return self._scan(lambda r: ip and ip in r.get("remote_ips", []), limit) if ip else []

    def lookup_domain(self, domain: str, limit: int = 20) -> list[dict]:
        d = (domain or "").lower()
        return self._scan(
            lambda r: d and any(d in q.lower() for q in r.get("dns", [])), limit) if d else []

    def lookup_repository(self, repo: str, limit: int = 20) -> list[dict]:
        r_ = (repo or "").lower()
        return self._scan(lambda r: r_ and r_ in r.get("repository", "").lower(), limit) if r_ else []

    def lookup_dependency(self, package: str, limit: int = 20) -> list[dict]:
        p = (package or "").lower()
        def has(r):
            for d in r.get("dependencies", []):
                pkgs = d.get("packages", []) if isinstance(d, dict) else [d]
                if any(p == str(x).lower() for x in pkgs):
                    return True
            return False
        return self._scan(has, limit) if p else []

    def lookup_behavior(self, fingerprint: str = "", signals: Optional[list] = None,
                        limit: int = 20) -> list[dict]:
        sig = set(signals or [])
        def match(r):
            if fingerprint and r.get("fingerprint") == fingerprint:
                return True
            if sig and sig.issubset(set(r.get("network_behavior", []))):
                return True
            return False
        return self._scan(match, limit) if (fingerprint or sig) else []

    def timeline(self, sha256: str = "", fingerprint: str = "", process: str = "",
                 repository: str = "") -> list[dict]:
        """All observations of one entity, oldest → newest (the history, req 3)."""
        recs = []
        if sha256:      recs = self.lookup_sha256(sha256, limit=_MAX_RECORDS)
        elif fingerprint: recs = self.lookup_behavior(fingerprint=fingerprint, limit=_MAX_RECORDS)
        elif repository: recs = self.lookup_repository(repository, limit=_MAX_RECORDS)
        elif process:   recs = self.lookup_process(process, limit=_MAX_RECORDS)
        return sorted(recs, key=lambda r: r.get("ts", ""))

    # ── enrichment (req 5, 6, 10) ──────────────────────────────────────────────

    def historical_context(self, sha256: str = "", process: str = "",
                           ips: Optional[list] = None, fingerprint: str = "",
                           repository: str = "") -> dict:
        """Search memory for anything matching this target and summarise the
        historical evidence. Called before analysis to enrich the verdict."""
        ips = ips or []
        seen: dict[int, dict] = {}          # object identity — records are shared refs
        for group in (
            self.lookup_sha256(sha256) if sha256 else [],
            self.lookup_behavior(fingerprint=fingerprint) if fingerprint else [],
            self.lookup_process(process) if process else [],
            self.lookup_repository(repository) if repository else [],
            *[self.lookup_ip(ip) for ip in ips],
        ):
            for r in group:
                seen[id(r)] = r
        recs = sorted(seen.values(), key=lambda r: r.get("ts", ""))
        if not recs:
            return {}

        all_ips = {ip for r in recs for ip in r.get("remote_ips", [])}
        all_asn = {a for r in recs for a in r.get("asn", [])}
        return {
            "seen_count":        len(recs),
            "first_seen":        recs[0].get("ts", ""),
            "last_seen":         recs[-1].get("ts", ""),
            "sha256_match":      bool(sha256) and any(r.get("sha256", "").lower() == sha256.lower() for r in recs),
            "fingerprint_match": bool(fingerprint) and any(r.get("fingerprint") == fingerprint for r in recs),
            "worst_verdict":     _worst([r.get("verdict", "") for r in recs]),
            "verdicts":          sorted({r.get("verdict", "?") for r in recs}),
            "matched_ips":       sorted(all_ips & set(ips)),
            "same_asn":          sorted(all_asn),
            "process_trees":     sorted({t for r in recs for t in r.get("process_tree", [])})[:5],
            "last_reason":       (recs[-1].get("network_behavior") or ["evidence on file"])[0],
        }

    # ── legacy facade (kept working) ───────────────────────────────────────────

    def retrieve_events(self, ip: str = "", process: str = "", port: int = 0,
                        days: int = 7, limit: int = 10) -> list[dict]:
        recs = []
        if ip:        recs = self.lookup_ip(ip, limit)
        elif process: recs = self.lookup_process(process, limit)
        elif port:    recs = self._scan(lambda r: port in r.get("ports", []), limit)
        return [self._to_event(r) for r in recs]

    def risk_history_lookup(self, ip: str = "", process: str = "") -> dict:
        ctx = self.historical_context(process=process, ips=[ip] if ip else [])
        if not ctx:
            return {}
        return {
            "hits": ctx["seen_count"], "worst": ctx["worst_verdict"] or "?",
            "last_ts": ctx["last_seen"], "last_reason": ctx["last_reason"],
        }

    def prior_decision_lookup(self, ip: str = "", process: str = "") -> Optional[str]:
        for r in (self.lookup_ip(ip) if ip else []) + (self.lookup_process(process) if process else []):
            for rule in r.get("policy_rules", []):
                if str(rule).startswith("decision:"):
                    return str(rule).split(":", 1)[1]
        return None

    def build_context(self, ip: str = "", process: str = "", port: int = 0) -> str:
        ctx = self.historical_context(process=process, ips=[ip] if ip else [])
        if not ctx:
            return ""
        lines = [f"[MEMORY] {line}" for line in evidence_summary(ctx)]
        decision = self.prior_decision_lookup(ip=ip, process=process)
        if decision:
            lines.append(f"[MEMORY] Prior decision: {decision}")
        return "\n".join(lines)

    @staticmethod
    def _to_event(rec: dict) -> dict:
        ips  = rec.get("remote_ips", [])
        beh  = rec.get("network_behavior", [])
        port = rec.get("ports", [0])
        return {
            "ts": rec.get("ts", ""), "level": rec.get("verdict", "?"),
            "reason": beh[0] if beh else "", "action": "",
            "process": rec.get("process", ""), "remote_ip": ips[0] if ips else "",
            "port": port[0] if port else 0, "exe": rec.get("exe", ""), "decision": "",
        }

    # ── server mirror + load ───────────────────────────────────────────────────

    def _load(self) -> None:
        try:
            if self._path.exists():
                with open(self._path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                self._recs.append(json.loads(line))
                            except Exception:
                                pass
        except Exception:
            pass
        # one-time migration of the old flat event file
        if not self._recs and _LEGACY_JSON.exists():
            try:
                for ev in json.loads(_LEGACY_JSON.read_text(encoding="utf-8")):
                    self._recs.append(_event_to_evidence(ev))
            except Exception:
                pass


def _record_to_text(rec: dict) -> str:
    """Compact human string for semantic indexing — deterministic evidence only."""
    parts = [f"[{rec.get('verdict', '?')}] {rec.get('process') or rec.get('repository') or 'target'}"]
    if rec.get("sha256"):        parts.append(f"sha256 {rec['sha256'][:16]}")
    if rec.get("remote_ips"):    parts.append("to " + ",".join(rec["remote_ips"][:3]))
    if rec.get("network_behavior"): parts.append("behavior: " + ", ".join(rec["network_behavior"][:4]))
    if rec.get("file_access"):   parts.append(f"{len(rec['file_access'])} sensitive file access")
    if rec.get("persistence"):   parts.append(f"{len(rec['persistence'])} persistence")
    if rec.get("policy_rules"):  parts.append("rules: " + ", ".join(map(str, rec["policy_rules"][:5])))
    parts.append(f"score {rec.get('risk_score', 0)} at {rec.get('ts', '?')}")
    return " | ".join(parts)


def demo() -> None:
    """Runnable proof: store forensic evidence, then find it every way. `python core/memory.py`"""
    import tempfile
    store = SuperMemory(path=Path(tempfile.mkdtemp()) / "evidence.jsonl")

    # a malicious sandbox run
    r1 = make_evidence(
        kind="sandbox", source="sandbox-runtime", sha256="a" * 64,
        process="update.exe", parent="powershell.exe",
        process_tree=["python > sh > npm > node"],
        processes=[{"comm": "node"}, {"comm": "curl"}],
        remote_ips=["45.33.32.156"], asn=["AS13335"], ports=[4444],
        network_behavior=["reverse_shell"], dns=["evil.example.com"],
        file_access=[{"path": "/root/.ssh/id_rsa", "category": "ssh_key"}],
        persistence=["/etc/cron.d"], dependencies=[{"manager": "npm", "packages": ["node-ipc"]}],
        policy_rules=["DECOY_CREDENTIAL_READ", "PERSISTENCE_WRITE"],
        risk_score=95, verdict="DANGEROUS", repository="/tmp/evil-repo",
    )
    fp = r1["fingerprint"]
    store.store_evidence(r1)

    # every lookup API finds it (req 4)
    assert store.lookup_sha256("a" * 64)
    assert store.lookup_process("update.exe")
    assert store.lookup_ip("45.33.32.156")
    assert store.lookup_domain("evil.example.com")
    assert store.lookup_repository("evil-repo")
    assert store.lookup_dependency("node-ipc")
    assert store.lookup_behavior(fingerprint=fp)

    # the SAME malware, renamed, with a different hash — matched by behavior (req 9)
    r2 = make_evidence(
        kind="sandbox", sha256="b" * 64, process="totally-legit.exe",
        process_tree=["python > sh > npm > node"],
        processes=[{"comm": "node"}, {"comm": "curl"}],
        network_behavior=["reverse_shell"],
        file_access=[{"path": "/home/u/.ssh/id_rsa", "category": "ssh_key"}],
        persistence=["/etc/cron.d"], dependencies=[{"manager": "npm", "packages": ["node-ipc"]}],
        risk_score=95, verdict="DANGEROUS",
    )
    assert r2["fingerprint"] == fp, "renamed malware must share a behavior fingerprint"
    store.store_evidence(r2)

    # enrichment before a fresh run: history is surfaced (req 5, 6, 10)
    ctx = store.historical_context(fingerprint=fp, ips=["45.33.32.156"])
    assert ctx["seen_count"] == 2
    assert ctx["worst_verdict"] == "DANGEROUS"
    assert ctx["fingerprint_match"]
    assert "AS13335" in ctx["same_asn"]
    lines = evidence_summary(ctx)
    assert any("Previously observed 2" in l for l in lines)
    assert any("Same ASN" in l for l in lines)

    # timeline is append-only, oldest→newest (req 3), and survives a reload
    assert len(store.timeline(fingerprint=fp)) == 2
    reloaded = SuperMemory(path=store._path)
    assert len(reloaded.lookup_sha256("a" * 64)) == 1

    # legacy facade still works
    store.store_event(make_event("CRITICAL", "C2 beacon", "block_ip", "x.exe", "1.2.3.4", 4444))
    assert store.risk_history_lookup(process="x.exe")["worst"] == "CRITICAL"

    print("memory.py self-check passed")


if __name__ == "__main__":
    demo()
