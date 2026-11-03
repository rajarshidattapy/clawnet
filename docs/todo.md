

Things you can add:

1. **Model router**: pick the model per task and fall back on errors, either in `core/[llm.py](http://llm.py)` or through a gateway.
2. **Observability**: add tracing (OpenTelemetry or Langfuse) plus token, cost and latency metrics.
3. **Quality evals**: add a golden set with an LLM judge, and run it in CI next to the existing safety replay.

