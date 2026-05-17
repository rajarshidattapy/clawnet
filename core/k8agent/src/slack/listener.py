"""Slack Socket Mode listener for conversational agent control."""
import asyncio
import json
import logging
import re
from slack_sdk.web.async_client import AsyncWebClient
from slack_sdk.socket_mode.aiohttp import SocketModeClient
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.socket_mode.response import SocketModeResponse

from core.k8agent.src.config import settings
from core.k8agent.src.llm.client import llm_call_sync

logger = logging.getLogger(__name__)

# Quick action patterns — order matters, first match wins
PATTERNS = {
    r"(?i)(status|health|how.*(cluster|pod)|what.*(broken|wrong|failing|down)|broken|failing|issue)": "cluster_status",
    r"(?i)(incident|history|audit|log)": "incident_query",
    r"(?i)(inject\s+chaos|trigger\s+chaos|chaos\s+inject|break\s+things)": "chaos_trigger",
    # NLP catch-all: action verbs that imply a kubectl command
    r"(?i)(fix|resolve|heal|remediate|restart|delete|kill|remove|increase|decrease|scale|rollback|undo|revert|describe|show\s+logs|get\s+logs|patch|bump|resize)": "nlp_command",
}


async def handle_message(client: SocketModeClient, req: SocketModeRequest):
    """Handle incoming Slack messages and app mentions."""
    if req.type == "events_api":
        response = SocketModeResponse(envelope_id=req.envelope_id)
        await client.send_socket_mode_response(response)

        event = req.payload.get("event", {})
        if event.get("type") in ("app_mention", "message") and not event.get("bot_id"):
            text = event.get("text", "")
            channel = event.get("channel", "")
            thread_ts = event.get("ts", "")

            # Remove bot mention
            text = re.sub(r"<@\w+>", "", text).strip()

            if not text:
                return

            # Determine intent
            intent = _classify_intent(text)
            response_text = await _handle_intent(intent, text)

            # Reply in thread
            web_client = AsyncWebClient(token=settings.SLACK_BOT_TOKEN)
            await web_client.chat_postMessage(
                channel=channel,
                thread_ts=thread_ts,
                text=response_text,
            )

    elif req.type == "interactive":
        # Handle block_actions (Approve / Reject button clicks)
        response = SocketModeResponse(envelope_id=req.envelope_id)
        await client.send_socket_mode_response(response)

        payload = req.payload
        actions = payload.get("actions", [])
        if actions:
            action = actions[0]
            action_id = action.get("action_id", "")
            try:
                value = json.loads(action.get("value", "{}"))
            except (json.JSONDecodeError, TypeError):
                value = {}

            thread_id = value.get("thread_id", "")
            username = payload.get("user", {}).get("username", "unknown")
            response_url = payload.get("response_url", "")
            approved = action_id == "approve"

            if thread_id and action_id in ("approve", "reject"):
                logger.info(
                    "Socket Mode interactive action: action=%s user=%s thread=%s",
                    action_id, username, thread_id,
                )
                # Resume graph in a background thread (graph.invoke is synchronous)
                asyncio.get_event_loop().run_in_executor(
                    None,
                    _resume_graph_sync,
                    thread_id,
                    approved,
                    username,
                    response_url,
                )

    elif req.type == "slash_commands":
        response = SocketModeResponse(envelope_id=req.envelope_id)
        await client.send_socket_mode_response(response)

        command = req.payload.get("command", "")
        text = req.payload.get("text", "")
        channel = req.payload.get("channel_id", "")

        response_text = await _handle_slash_command(command, text)

        web_client = AsyncWebClient(token=settings.SLACK_BOT_TOKEN)
        await web_client.chat_postMessage(channel=channel, text=response_text)


def _classify_intent(text: str) -> str:
    for pattern, intent in PATTERNS.items():
        if re.search(pattern, text):
            return intent
    return "general_query"


async def _handle_intent(intent: str, text: str) -> str:
    if intent == "cluster_status":
        return await _get_cluster_status()
    elif intent == "nlp_command":
        return await _handle_nlp_command(text)
    elif intent == "incident_query":
        return await _get_recent_incidents()
    elif intent == "chaos_trigger":
        return await _trigger_chaos()
    else:
        return await _general_chat(text)


async def _get_cluster_status() -> str:
    try:
        from core.k8agent.src.mcp_server.kubectl_tools import get_pods, get_nodes

        pods = get_pods()
        nodes = get_nodes()

        total = len(pods) if isinstance(pods, list) else 0
        running = (
            sum(1 for p in pods if isinstance(p, dict) and p.get("phase") == "Running")
            if isinstance(pods, list)
            else 0
        )

        return (
            f"*Cluster Status*\n"
            f"  Pods: {running}/{total} running\n"
            f"  Nodes: {len(nodes) if isinstance(nodes, list) else 'unknown'}\n"
            f"  Namespace: {settings.NAMESPACE}"
        )
    except Exception as e:
        return f"Error fetching cluster status: {e}"


async def _handle_nlp_command(text: str) -> str:
    """Use LLM to parse natural language into a kubectl action, then execute."""
    import json as _json

    system = (
        "You are a Kubernetes assistant. Parse the user's request into a JSON action.\n"
        "Output ONLY valid JSON with these fields:\n"
        '- action: one of "delete_pod", "patch_resources", "rollback", "scale", "status", "describe", "logs"\n'
        '- target: the pod or deployment name mentioned (or "all" if not specific)\n'
        '- namespace: default "k8swhisperer-demo"\n'
        '- params: any extra params like {"memory": "128Mi"}\n\n'
        "If the user just wants info, use action \"status\".\n"
        "Examples:\n"
        '"delete the crashloop pod" -> {"action": "delete_pod", "target": "crashloop-demo", "namespace": "k8swhisperer-demo"}\n'
        '"increase memory for oomkill" -> {"action": "patch_resources", "target": "oomkill-deploy-demo", "namespace": "k8swhisperer-demo", "params": {"memory": "128Mi"}}\n'
        '"what\'s broken?" -> {"action": "status", "target": "all", "namespace": "k8swhisperer-demo"}'
    )

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": text},
    ]

    try:
        response = await asyncio.to_thread(llm_call_sync, messages)
    except Exception as e:
        logger.error("LLM call failed for NLP command: %s", e)
        return f"Error understanding your request: {e}"

    try:
        plan = _json.loads(response)
    except Exception:
        return f"I understood your request but couldn't parse it into an action. Raw: {response[:200]}"

    action = plan.get("action", "status")
    target = plan.get("target", "")
    namespace = plan.get("namespace", "k8swhisperer-demo")

    try:
        if action == "delete_pod":
            from core.k8agent.src.mcp_server.kubectl_tools import delete_pod
            result = delete_pod(name=target, namespace=namespace)
            return f"Deleted pod `{target}`: {result.get('status', result.get('error', 'unknown'))}"

        elif action == "patch_resources":
            from core.k8agent.src.mcp_server.kubectl_tools import patch_deployment_resources
            params = plan.get("params", {})
            result = patch_deployment_resources(
                name=target,
                namespace=namespace,
                memory_limit=params.get("memory", ""),
                cpu_limit=params.get("cpu", ""),
            )
            return f"Patched `{target}`: {result.get('status', result.get('error', 'unknown'))}"

        elif action == "rollback":
            from core.k8agent.src.mcp_server.kubectl_tools import rollback_deployment
            result = rollback_deployment(name=target, namespace=namespace)
            return f"Rollback `{target}`: {result.get('status', result.get('error', 'unknown'))}"

        elif action == "logs":
            from core.k8agent.src.mcp_server.kubectl_tools import get_pod_logs
            result = get_pod_logs(name=target, namespace=namespace, tail_lines=20)
            return f"Last 20 lines of `{target}`:\n```\n{result if isinstance(result, str) else str(result)[:500]}\n```"

        elif action == "describe":
            from core.k8agent.src.mcp_server.kubectl_tools import describe_pod
            result = describe_pod(name=target, namespace=namespace)
            return f"Describe `{target}`:\n```\n{str(result)[:500]}\n```"

        elif action == "scale":
            # Scale not yet implemented as a tool — fall back to general chat
            return await _general_chat(f"Scale request for {target}: {text}")

        else:  # status
            return await _get_cluster_status()

    except Exception as e:
        logger.error("NLP command execution failed: action=%s target=%s error=%s", action, target, e)
        return f"Error executing {action} on `{target}`: {e}"


async def _get_recent_incidents() -> str:
    try:
        import json
        from pathlib import Path

        from core.k8agent.src.utils.audit import AUDIT_LOG_PATH as audit_path
        if not audit_path.exists():
            return "No incidents recorded yet."
        entries = json.loads(audit_path.read_text())
        recent = entries[-5:] if len(entries) > 5 else entries
        lines = []
        for e in recent:
            lines.append(
                f"  `{e.get('incident_id', 'unknown')[:12]}` | "
                f"{e.get('stage', '?')} | {e.get('outcome', '?')}"
            )
        return f"*Recent Incidents ({len(entries)} total)*\n" + "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


async def _trigger_chaos() -> str:
    try:
        from core.k8agent.src.chaos.injector import inject_chaos

        results = await inject_chaos(count=2)
        names = (
            [r.get("scenario", "unknown") for r in results]
            if isinstance(results, list)
            else ["chaos injected"]
        )
        return f"Chaos injected: {', '.join(names)}"
    except Exception as e:
        return f"Chaos injection failed: {e}"


async def _general_chat(text: str) -> str:
    try:
        # Get real cluster context
        cluster_ctx = ""
        try:
            from core.k8agent.src.mcp_server.kubectl_tools import get_pods
            pods = get_pods()
            if isinstance(pods, list):
                lines = []
                for p in pods:
                    if isinstance(p, dict) and "name" in p:
                        phase = p.get("phase", "?")
                        restarts = sum(c.get("restart_count", 0) for c in p.get("container_statuses", []) if isinstance(c, dict))
                        lines.append(f"  - {p['name']}: {phase} (restarts={restarts})")
                cluster_ctx = "\n\nCurrent pods:\n" + "\n".join(lines) if lines else "\n\nNo pods running."
        except Exception:
            cluster_ctx = "\n\n(Could not fetch cluster state)"

        messages = [
            {
                "role": "system",
                "content": (
                    "You are K8sWhisperer, an AI Kubernetes incident response agent. "
                    "You have access to a live kind cluster. Answer questions about cluster health, "
                    "incidents, and remediation strategies. Be concise and actionable."
                    f"{cluster_ctx}"
                ),
            },
            {"role": "user", "content": text},
        ]
        response = await asyncio.to_thread(llm_call_sync, messages)
        return response or "I couldn't generate a response. Try asking about cluster status or recent incidents."
    except Exception as e:
        return f"Error: {e}"


async def _handle_slash_command(command: str, text: str) -> str:
    if command == "/k8s":
        if not text:
            return (
                "*K8sWhisperer Commands*\n"
                "  `/k8s status` - Cluster health\n"
                "  `/k8s incidents` - Recent incidents\n"
                "  `/k8s chaos` - Inject failures\n"
                "  `/k8s fix` - Trigger scan & remediation"
            )
        return await _handle_intent(_classify_intent(text), text)
    return "Unknown command"


def _resume_graph_sync(
    thread_id: str,
    approved: bool,
    username: str,
    response_url: str,
) -> None:
    """Resume the LangGraph pipeline after an Approve/Reject button click.

    Runs in a thread-pool executor because graph.invoke() is synchronous.
    """
    from langgraph.types import Command
    from core.k8agent.src.graph.builder import graph

    import httpx

    decision_text = "approved" if approved else "rejected"

    try:
        config = {"configurable": {"thread_id": thread_id}}
        graph.invoke(
            Command(resume={"approved": approved, "user": username}),
            config=config,
        )
        logger.info(
            "Graph resumed for thread %s — %s by %s",
            thread_id, decision_text, username,
        )
    except Exception:
        logger.exception("Failed to resume graph for thread %s", thread_id)

    # Update Slack message via response_url
    if response_url:
        try:
            httpx.post(
                response_url,
                json={
                    "replace_original": True,
                    "text": f":memo: Remediation *{decision_text}* by *{username}*.",
                },
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
        except Exception:
            logger.warning("Failed to update Slack message via response_url", exc_info=True)


async def start_socket_mode():
    """Start Slack Socket Mode listener."""
    if not settings.SLACK_APP_TOKEN:
        logger.warning("SLACK_APP_TOKEN not set, skipping Socket Mode listener")
        return

    client = SocketModeClient(
        app_token=settings.SLACK_APP_TOKEN,
        web_client=AsyncWebClient(token=settings.SLACK_BOT_TOKEN),
    )
    client.socket_mode_request_listeners.append(handle_message)

    logger.info("Starting Slack Socket Mode listener...")
    await client.connect()

    # Keep alive
    while True:
        await asyncio.sleep(1)
