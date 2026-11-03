"""Keep test runs away from the real ~/.clawnet: traces and the LLM cache go to a temp dir."""
import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="clawnet-tests-")
os.environ["TELEMETRY_PATH"] = os.path.join(_TMP, "traces.jsonl")
os.environ.setdefault("CLAWNET_LLM_CACHE_PATH", os.path.join(_TMP, "llm_cache.json"))
