

Things you can add:

1. **RBAC**: map roles to the existing `CONTROL_TOOLS` and `EXECUTE_TOOLS` tiers, and log the caller in `decisions.jsonl`.

2. **Model router**: pick the model per task and fall back on errors, either in `core/[llm.py](http://llm.py)` or through a gateway like LiteLLM.

3. **LLM response cache**: key it on the scrubbed prompt hash and persist it across restarts.

4. **Observability**: add tracing (OpenTelemetry or Langfuse) plus token, cost and latency metrics.

5. **Output guardrails**: redact secrets and PII in model output, and validate proposed actions against a schema.

6. **Quality evals**: add a golden set with an LLM judge, and run it in CI next to the existing safety replay.

I'd start with 1 and 2, then 5.