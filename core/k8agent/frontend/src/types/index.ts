export interface Incident {
  incident_id: string;
  first_seen: string;
  last_seen: string;
  stages: string[];
  summary: string;
  outcome: string;
  anomaly_type?: string;
  severity?: string;
  affected_resource?: string;
  namespace?: string;
  confidence?: number;
  action?: string;
  blast_radius?: string;
}

export interface PodStatus {
  name: string;
  namespace: string;
  phase: string;
  node: string;
  containers: ContainerStatus[];
}

export interface ContainerStatus {
  name: string;
  ready: boolean;
  restart_count: number;
  state: string;
  reason?: string;
  image: string;
}

export interface NodeStatus {
  name: string;
  conditions: { type: string; status: string }[];
}

export interface ClusterState {
  pods: PodStatus[];
  nodes: NodeStatus[];
}

export interface ChatMessage {
  role: "user" | "agent";
  content: string;
  timestamp?: string;
}

export interface ChaosResult {
  scenarios: { scenario: string; applied_at: string }[];
}

export interface AuditEntry {
  incident_id: string;
  timestamp: string;
  stage: string;
  summary: string;
  details: Record<string, unknown>;
  decision: string;
  outcome: string;
}

export interface Trace {
  trace_id: string;
  stage: string;
  model: string;
  input_preview: string;
  output_preview: string;
  input_full?: string;
  output_full?: string;
  input_chars: number;
  output_chars: number;
  duration_ms: number;
  timestamp: string;
}

export interface BlockchainStatus {
  enabled: boolean;
  network: string;
  contract_id: string;
  incident_count: number;
  connection: string;
}

export interface BlockchainIncident {
  incident_id: string;
  anomaly_type: string;
  action: string;
  timestamp: string;
  confidence: number;
  auto_executed: boolean;
  decision: string;
  explorer_url?: string;
}
