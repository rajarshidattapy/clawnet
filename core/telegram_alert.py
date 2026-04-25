"""Telegram alert and remote-command bot for ClawNet v2/v3."""
import asyncio
import os
import random
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

try:
    from telegram import Bot, Update
    from telegram.ext import Application, CommandHandler, ContextTypes
    _HAS_PTB = True
except ImportError:
    _HAS_PTB = False


@dataclass
class PendingAction:
    action_id: str
    pid: Optional[int]
    remote_ip: str
    process: str
    action_type: str   # "kill_process" | "block_ip" | "kill_and_block"
    reason: str
    approved: Optional[bool] = None


class TelegramAlert:
    """Sends threat alerts and handles remote approval commands via Telegram."""

    def __init__(self, token: str, chat_id: str = "") -> None:
        self._token    = token.strip()
        self._chat_id  = chat_id.strip()
        self._pending: dict[str, PendingAction] = {}
        self._lock     = threading.Lock()
        self._execute_cb: Optional[Callable[[PendingAction], None]] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._app      = None
        self._status   = "initializing…"

        self.available = _HAS_PTB and bool(self._token)
        self.ready     = self.available and bool(self._chat_id)

        if self.available:
            threading.Thread(target=self._run_thread, daemon=True, name="tg-bot").start()

    # ── public API ────────────────────────────────────────────────────────────

    @property
    def status(self) -> str:
        with self._lock:
            return self._status

    def set_execute_callback(self, cb: Callable[[PendingAction], None]) -> None:
        self._execute_cb = cb

    def send_alert(self, text: str) -> None:
        if not self.ready or not self._loop:
            return
        asyncio.run_coroutine_threadsafe(self._do_send(text), self._loop)

    def add_pending(self, action: PendingAction) -> None:
        with self._lock:
            self._pending[action.action_id] = action
        icon = "🔴" if "kill" in action.action_type else "🟡"
        self.send_alert(
            f"{icon} <b>Action Required — ClawNet</b>\n"
            f"Process: <code>{action.process}</code>  PID: <code>{action.pid}</code>\n"
            f"Remote IP: <code>{action.remote_ip}</code>\n"
            f"Proposed: <b>{action.action_type}</b>\n"
            f"Reason: {action.reason}\n\n"
            f"✅ /approve {action.action_id}\n"
            f"❌ /deny {action.action_id}"
        )

    def get_pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    # ── threading / asyncio ───────────────────────────────────────────────────

    def _run_thread(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._bot_main())

    async def _bot_main(self) -> None:
        try:
            self._app = Application.builder().token(self._token).build()
            for name, handler in [
                ("start",   self._cmd_start),
                ("approve", self._cmd_approve),
                ("deny",    self._cmd_deny),
                ("kill",    self._cmd_kill),
                ("block",   self._cmd_block),
                ("status",  self._cmd_status),
            ]:
                self._app.add_handler(CommandHandler(name, handler))
            await self._app.initialize()
            await self._app.start()
            await self._app.updater.start_polling(drop_pending_updates=True)
            with self._lock:
                self._status = "connected"
            await asyncio.Event().wait()
        except Exception as exc:
            with self._lock:
                self._status = f"error: {str(exc)[:60]}"

    async def _do_send(self, text: str) -> None:
        try:
            await self._app.bot.send_message(
                chat_id=self._chat_id, text=text, parse_mode="HTML"
            )
        except Exception as exc:
            with self._lock:
                self._status = f"send-error: {str(exc)[:50]}"

    # ── command handlers ──────────────────────────────────────────────────────

    async def _cmd_start(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        cid = str(update.effective_chat.id)
        if not self._chat_id:
            self._chat_id = cid
            self.ready    = True
            _persist_chat_id(cid)
            with self._lock:
                self._status = "connected"
        await update.message.reply_html(
            f"🐾 <b>ClawNet v2 Active</b>\n"
            f"Chat ID: <code>{cid}</code>\n\n"
            "/status — pending approvals\n"
            "/approve &lt;id&gt; — approve action\n"
            "/deny &lt;id&gt; — deny action\n"
            "/kill &lt;pid&gt; — kill process now\n"
            "/block &lt;ip&gt; — block IP now"
        )

    async def _cmd_approve(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        args = ctx.args
        if not args:
            await update.message.reply_text("Usage: /approve <action_id>")
            return
        aid = args[0]
        with self._lock:
            action = self._pending.pop(aid, None)
        if not action:
            await update.message.reply_text(f"No pending action: {aid}")
            return
        action.approved = True
        if self._execute_cb:
            threading.Thread(target=self._execute_cb, args=(action,), daemon=True).start()
        await update.message.reply_text(
            f"✅ Approved: {action.action_type}\n"
            f"Process: {action.process} (PID {action.pid})"
        )

    async def _cmd_deny(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        args = ctx.args
        if not args:
            await update.message.reply_text("Usage: /deny <action_id>")
            return
        aid = args[0]
        with self._lock:
            removed = self._pending.pop(aid, None)
        msg = (
            f"❌ Denied: {removed.action_type} on {removed.process}"
            if removed else f"Not found: {aid}"
        )
        await update.message.reply_text(msg)

    async def _cmd_kill(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        args = ctx.args
        if not args:
            await update.message.reply_text("Usage: /kill <pid>")
            return
        try:
            pid = int(args[0])
        except ValueError:
            await update.message.reply_text("PID must be a number")
            return
        action = PendingAction(
            action_id=f"tg-kill-{pid}", pid=pid, remote_ip="",
            process=f"pid:{pid}", action_type="kill_process",
            reason="Direct kill via Telegram",
        )
        if self._execute_cb:
            threading.Thread(target=self._execute_cb, args=(action,), daemon=True).start()
        await update.message.reply_text(f"⚡ Kill signal sent to PID {pid}")

    async def _cmd_block(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        args = ctx.args
        if not args:
            await update.message.reply_text("Usage: /block <ip>")
            return
        ip = args[0]
        action = PendingAction(
            action_id=f"tg-block-{ip.replace('.', '-')}",
            pid=None, remote_ip=ip, process="",
            action_type="block_ip", reason="Manual block via Telegram",
        )
        if self._execute_cb:
            threading.Thread(target=self._execute_cb, args=(action,), daemon=True).start()
        await update.message.reply_text(f"🚫 Blocking {ip}…")

    async def _cmd_status(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        with self._lock:
            pending = list(self._pending.values())
        if not pending:
            await update.message.reply_text("✅ No pending actions.")
            return
        lines = ["⏳ <b>Pending Actions:</b>"]
        for p in pending:
            lines.append(f"• <code>{p.action_id}</code> — {p.action_type} → {p.process}")
        await update.message.reply_html("\n".join(lines))


# ── Telegram mock scheduler ───────────────────────────────────────────────────

_MOCK_MESSAGES = {
    "LOW": [
        "System healthy — no suspicious activity detected",
        "All connections nominal — ClawNet watching",
        "Network scan complete — no threats found",
        "VPN active — traffic secured",
        "DNS resolution normal — no anomalies",
    ],
    "MED": [
        "Medium risk detected — unusual outbound traffic from node.exe",
        "Elevated DNS activity on port 53 — monitoring",
        "New foreign connection detected — pending AI analysis",
        "Process running from Downloads folder — flagged for review",
        "High port usage spike — possible scan activity",
    ],
    "HIGH": [
        "HIGH ALERT — suspicious process connecting to foreign IP",
        "VPN disconnected — traffic exposed on public WiFi",
        "Possible C2 beacon detected — process: svchost.exe",
        "CRITICAL — connection to known malicious ASN blocked",
        "Unsigned binary spawned network connection — immediate review needed",
    ],
}

_SEVERITY_WEIGHTS = [("LOW", 70), ("MED", 20), ("HIGH", 10)]


def _weighted_pick() -> tuple[str, str]:
    pool = [sev for sev, w in _SEVERITY_WEIGHTS for _ in range(w)]
    sev  = random.choice(pool)
    msg  = random.choice(_MOCK_MESSAGES[sev])
    return sev, msg


class TelegramMock:
    """Sends simulated device-status updates at random intervals (demo/test)."""

    def __init__(
        self,
        alert: "TelegramAlert",
        min_interval: int = 60,
        max_interval: int = 300,
    ) -> None:
        self._alert   = alert
        self._min     = min_interval
        self._max     = max_interval
        self._running = False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        threading.Thread(target=self._loop, daemon=True, name="tg-mock").start()

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            delay = random.randint(self._min, self._max)
            time.sleep(delay)
            if not self._running:
                break
            try:
                sev, msg = _weighted_pick()
                icon = {"LOW": "✅", "MED": "⚠️", "HIGH": "🚨"}[sev]
                self._alert.send_alert(f"{icon} <b>[{sev}]</b> {msg}")
            except Exception:
                pass


def _persist_chat_id(chat_id: str) -> None:
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    try:
        with open(env_path, "r") as f:
            content = f.read()
        if "TELEGRAM_CHAT_ID=" in content:
            lines = [
                (f"TELEGRAM_CHAT_ID={chat_id}" if ln.startswith("TELEGRAM_CHAT_ID=") else ln)
                for ln in content.splitlines()
            ]
            new_content = "\n".join(lines) + "\n"
        else:
            new_content = content.rstrip("\n") + f"\nTELEGRAM_CHAT_ID={chat_id}\n"
        with open(env_path, "w") as f:
            f.write(new_content)
    except Exception:
        pass
