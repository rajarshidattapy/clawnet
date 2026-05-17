import { useState, useRef, useEffect } from "react";
import {
  Send,
  Bot,
  User,
  Radio,
  Shield,
  Activity,
  MessageSquare,
  Terminal,
  AlertTriangle,
  Zap,
} from "lucide-react";
import { sendChat } from "../lib/api";
import type { ChatMessage } from "../types";

/* ------------------------------------------------------------------ */
/*  Markdown-lite renderer                                             */
/* ------------------------------------------------------------------ */

function renderContent(raw: string) {
  // Split on fenced code blocks first (```...```)
  const fencedParts = raw.split(/(```[\s\S]*?```)/g);

  const elements: React.ReactNode[] = [];

  fencedParts.forEach((segment, si) => {
    if (segment.startsWith("```") && segment.endsWith("```")) {
      const inner = segment.slice(3, -3).replace(/^\w*\n/, ""); // strip optional lang hint
      elements.push(
        <pre
          key={`fenced-${si}`}
          className="my-2 rounded-lg bg-black/40 border border-slate-700/60 px-3 py-2 text-xs leading-relaxed overflow-x-auto whitespace-pre font-mono text-cyan-300/90"
        >
          {inner}
        </pre>,
      );
      return;
    }

    // For non-fenced segments, process inline formatting line-by-line
    const lines = segment.split("\n");
    lines.forEach((line, li) => {
      // Process inline code and bold within a line
      const tokens = line.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
      const inlineElements = tokens.map((tok, ti) => {
        if (tok.startsWith("`") && tok.endsWith("`")) {
          return (
            <code
              key={ti}
              className="px-1.5 py-0.5 rounded bg-black/30 border border-slate-700/50 text-cyan-400 text-xs font-mono"
            >
              {tok.slice(1, -1)}
            </code>
          );
        }
        if (tok.startsWith("**") && tok.endsWith("**")) {
          return (
            <strong key={ti} className="font-semibold text-slate-100">
              {tok.slice(2, -2)}
            </strong>
          );
        }
        return <span key={ti}>{tok}</span>;
      });

      elements.push(<span key={`line-${si}-${li}`}>{inlineElements}</span>);
      if (li < lines.length - 1) elements.push(<br key={`br-${si}-${li}`} />);
    });
  });

  return elements;
}

/* ------------------------------------------------------------------ */
/*  Quick-action chip data                                             */
/* ------------------------------------------------------------------ */

const QUICK_ACTIONS = [
  { label: "Cluster Status", icon: Activity, prompt: "Show me the current cluster status" },
  { label: "Recent Incidents", icon: AlertTriangle, prompt: "List recent incidents" },
  { label: "Health Check", icon: Zap, prompt: "Run a health check on the cluster" },
];

/* ------------------------------------------------------------------ */
/*  Main component                                                     */
/* ------------------------------------------------------------------ */

export default function WarRoom() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Auto-scroll on new messages or loading state change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  // Focus input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const agentCount = 1; // static for demo

  /* ---- send handler ---- */
  const handleSend = async (text?: string) => {
    const msg = (text ?? input).trim();
    if (!msg || loading) return;

    const userMsg: ChatMessage = {
      role: "user",
      content: msg,
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const response = await sendChat(msg);
      setMessages((prev) => [
        ...prev,
        {
          role: "agent",
          content:
            (response as any).response ??
            (response as any).content ??
            String(response),
          timestamp: new Date().toISOString(),
        },
      ]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: "agent",
          content: `Error: ${err instanceof Error ? err.message : "Failed to reach agent"}`,
          timestamp: new Date().toISOString(),
        },
      ]);
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  /* ---- derived ---- */
  const messageCount = messages.length;

  /* ---- time display memoised ---- */
  const formatTime = (iso?: string) => {
    if (!iso) return "";
    return new Date(iso).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div className="flex flex-col h-[calc(100vh-180px)] bg-gradient-to-b from-slate-900/80 to-slate-950/90 rounded-2xl border border-slate-700/40 shadow-2xl shadow-black/30 overflow-hidden">
      {/* ===== Header ===== */}
      <header className="px-5 py-3.5 border-b border-slate-700/40 bg-slate-900/60 backdrop-blur flex items-center gap-3">
        {/* Live dot + title */}
        <div className="flex items-center gap-2.5">
          <span className="relative flex h-2.5 w-2.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500" />
          </span>
          <Shield size={16} className="text-cyan-500" />
          <span className="text-sm font-semibold tracking-wide text-slate-200 uppercase">
            War Room
          </span>
        </div>

        {/* Spacer */}
        <div className="flex-1" />

        {/* Stats pills */}
        <div className="flex items-center gap-3 text-xs font-mono text-slate-500">
          <span className="flex items-center gap-1.5 bg-slate-800/60 border border-slate-700/40 rounded-full px-2.5 py-1">
            <Radio size={11} className="text-emerald-400" />
            {agentCount} agent{agentCount !== 1 ? "s" : ""}
          </span>
          <span className="flex items-center gap-1.5 bg-slate-800/60 border border-slate-700/40 rounded-full px-2.5 py-1">
            <MessageSquare size={11} className="text-cyan-400" />
            {messageCount} msg{messageCount !== 1 ? "s" : ""}
          </span>
        </div>
      </header>

      {/* ===== Messages area ===== */}
      <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
        {/* Empty state */}
        {messages.length === 0 && !loading && (
          <div className="flex flex-col items-center justify-center h-full text-center select-none animate-[fadeIn_0.5s_ease]">
            <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mb-5">
              <Terminal size={28} className="text-cyan-500/70" />
            </div>
            <h3 className="text-base font-semibold text-slate-300 mb-1">
              K8sWhisperer War Room
            </h3>
            <p className="text-sm text-slate-500 max-w-sm leading-relaxed">
              Investigate incidents, inspect cluster health, and coordinate
              remediation. Start by sending a message or choosing a quick action
              below.
            </p>
          </div>
        )}

        {/* Message list */}
        {messages.map((msg, i) => {
          const isAgent = msg.role === "agent";
          return (
            <div
              key={i}
              className={`flex gap-3 animate-[slideUp_0.25s_ease] ${
                isAgent ? "" : "flex-row-reverse"
              }`}
            >
              {/* Avatar */}
              <div
                className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5 ${
                  isAgent
                    ? "bg-cyan-500/15 text-cyan-400 ring-1 ring-cyan-500/20"
                    : "bg-slate-700/80 text-slate-300 ring-1 ring-slate-600/40"
                }`}
              >
                {isAgent ? <Bot size={16} /> : <User size={16} />}
              </div>

              {/* Bubble */}
              <div
                className={`max-w-[78%] rounded-xl px-4 py-3 ${
                  isAgent
                    ? "bg-slate-900/70 border-l-2 border-cyan-500/50 border-y border-r border-y-slate-700/30 border-r-slate-700/30 text-slate-300"
                    : "bg-cyan-500/10 border border-cyan-500/20 text-cyan-50"
                }`}
              >
                <div className="text-sm font-mono leading-relaxed whitespace-pre-wrap break-words">
                  {renderContent(msg.content)}
                </div>
                {msg.timestamp && (
                  <span
                    className={`text-[10px] font-mono mt-1.5 block ${
                      isAgent ? "text-slate-600" : "text-cyan-500/40"
                    }`}
                  >
                    {formatTime(msg.timestamp)}
                  </span>
                )}
              </div>
            </div>
          );
        })}

        {/* Typing indicator */}
        {loading && (
          <div className="flex gap-3 animate-[slideUp_0.2s_ease]">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 bg-cyan-500/15 text-cyan-400 ring-1 ring-cyan-500/20 mt-0.5">
              <Bot size={16} />
            </div>
            <div className="bg-slate-900/70 border-l-2 border-cyan-500/50 border-y border-r border-y-slate-700/30 border-r-slate-700/30 rounded-xl px-4 py-3">
              <div className="flex items-center gap-2">
                <div className="flex gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 typing-dot" />
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 typing-dot" />
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 typing-dot" />
                </div>
                <span className="text-xs text-slate-500 font-mono">
                  Agent is analyzing...
                </span>
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* ===== Bottom input area ===== */}
      <div className="border-t border-slate-700/40 bg-slate-900/40 backdrop-blur">
        {/* Quick actions */}
        <div className="flex items-center gap-2 px-5 pt-3 pb-1">
          {QUICK_ACTIONS.map((qa) => (
            <button
              key={qa.label}
              onClick={() => handleSend(qa.prompt)}
              disabled={loading}
              className="flex items-center gap-1.5 text-xs font-mono text-slate-400 bg-slate-800/60 hover:bg-slate-800 border border-slate-700/50 hover:border-cyan-500/30 hover:text-cyan-400 rounded-full px-3 py-1.5 transition-all duration-150 disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer"
            >
              <qa.icon size={12} />
              {qa.label}
            </button>
          ))}
        </div>

        {/* Input row */}
        <div className="flex items-center gap-3 px-5 pb-4 pt-2">
          <div className="relative flex-1">
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Describe an issue or ask about cluster state..."
              className="w-full bg-slate-950/60 border border-slate-700/50 focus:border-cyan-500/50 rounded-xl pl-4 pr-20 py-3 text-sm font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500/20 transition-all duration-200"
              disabled={loading}
            />
            <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] font-mono text-slate-600 pointer-events-none hidden sm:inline">
              Enter &crarr;
            </span>
          </div>
          <button
            onClick={() => handleSend()}
            disabled={loading || !input.trim()}
            className="w-11 h-11 flex items-center justify-center rounded-xl bg-cyan-500/15 border border-cyan-500/25 text-cyan-400 hover:bg-cyan-500/25 hover:border-cyan-500/40 active:scale-95 disabled:opacity-25 disabled:cursor-not-allowed transition-all duration-150 cursor-pointer"
          >
            <Send size={17} />
          </button>
        </div>
      </div>
    </div>
  );
}
