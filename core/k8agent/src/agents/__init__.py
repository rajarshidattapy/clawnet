"""K8sWhisperer multi-agent swarm system.

Agents:
    scout_agent     -- cluster reconnaissance (Sonnet)
    doctor_agent    -- root cause analysis (Opus)
    executor_agent  -- safe remediation (Sonnet)
    comms_agent     -- incident communications (Sonnet)
    commander_graph -- supervisor that coordinates all agents (Opus)

Convenience:
    run_incident_response(description) -- run the full incident pipeline
"""

from core.k8agent.src.agents.comms import comms_agent
from core.k8agent.src.agents.commander import commander_graph, run_incident_response
from core.k8agent.src.agents.doctor import doctor_agent
from core.k8agent.src.agents.executor import executor_agent
from core.k8agent.src.agents.scout import scout_agent

__all__ = [
    "scout_agent",
    "doctor_agent",
    "executor_agent",
    "comms_agent",
    "commander_graph",
    "run_incident_response",
]
