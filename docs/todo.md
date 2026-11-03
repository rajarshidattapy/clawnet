

Things you can add:

1. **Model router**: pick the model per task and fall back on errors, either in `core/[llm.py](http://llm.py)` or through a gateway.
2. **Observability**: add tracing - everything that langfuse does to monitor - plus token, cost and latency metrics. (don't add langfuse or stuff) - write your own tracing, add /settings in TUI so that I can see dashboard in tui for monitoring and stuff

