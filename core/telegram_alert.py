"""Telegram alert via HTTP API only - no external dependencies."""
import os
import json
import random
import time
import threading
from html import escape as _html_escape
from dataclasses import dataclass
from typing import Optional

try:
    import urllib.request
    import urllib.parse
    import urllib.error
    _HAS_URLLIB = True
except ImportError:
    _HAS_URLLIB = False


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
    """Send threat alerts via Telegram HTTP API (no external dependencies)."""

    def __init__(
        self, 
        token: str, 
        chat_id: str = "",
        backend_url: str = "",
        message_handler = None,
    ) -> None:
        self._token = token.strip()
        self._chat_id = chat_id.strip()
        self._base_url = f"https://api.telegram.org/bot{self._token}" if self._token else ""
        self._backend_url = backend_url.strip()
        self._message_handler = message_handler  # Callback(user_id, username, message) -> reply
        self._status = "initializing"
        self._update_offset = 0
        self._polling = False
        
        self.available = _HAS_URLLIB and bool(self._token)
        self.ready = self.available and bool(self._chat_id)
        
        if not self.ready and self.available:
            self._status = "warning: TELEGRAM_CHAT_ID not configured"
        elif self.ready:
            self._status = "ready"

    @property
    def status(self) -> str:
        """Current status of the bot."""
        return self._status

    def set_execute_callback(self, callback) -> None:
        """Stub for compatibility with old API (HTTP-only doesn't support callbacks)."""
        pass

    def add_pending(self, action: "PendingAction") -> None:
        """Stub for compatibility with old API (HTTP-only doesn't support pending actions)."""
        pass

    def get_pending_count(self) -> int:
        """Stub for compatibility with old API (HTTP-only doesn't track pending actions)."""
        return 0

    def set_message_handler(self, handler) -> None:
        """Set a callback to handle incoming messages.
        
        Handler signature: handler(user_id, username, message) -> reply_text
        """
        self._message_handler = handler

    def start_polling(self, poll_interval: int = 2) -> None:
        """Start background thread to poll for incoming messages."""
        if self._polling:
            return
        self._polling = True
        threading.Thread(
            target=self._poll_messages,
            args=(poll_interval,),
            daemon=True,
            name="tg-polling"
        ).start()

    def stop_polling(self) -> None:
        """Stop message polling."""
        self._polling = False

    def _poll_messages(self, poll_interval: int) -> None:
        """Background thread: poll for messages and process them."""
        while self._polling:
            try:
                updates = self.get_updates(offset=self._update_offset)
                for update in updates:
                    self._process_update(update)
                    self._update_offset = update.get("update_id", 0) + 1
                
                if not updates:
                    time.sleep(poll_interval)
            except Exception:
                time.sleep(poll_interval)

    def _process_update(self, update: dict) -> None:
        """Process a single update from Telegram."""
        message = update.get("message")
        if not message:
            return
        
        user_id = message.get("from", {}).get("id")
        username = message.get("from", {}).get("username", "unknown")
        text = message.get("text", "")
        message_id = message.get("message_id")
        
        if not text or not user_id:
            return
        
        try:
            # Try to send to backend if configured
            if self._backend_url:
                reply = self._forward_to_backend(user_id, username, text)
            elif self._message_handler:
                reply = self._message_handler(user_id, username, text)
            else:
                reply = "Message received (no handler configured)"
            
            # Send reply back to user
            if reply and message_id:
                self.send_reply(message_id, reply)
        
        except Exception:
            pass

    def _forward_to_backend(self, user_id: int, username: str, message: str) -> str:
        """Forward message to backend API and get reply.
        
        Args:
            user_id: Telegram user ID
            username: Telegram username
            message: Message text
            
        Returns:
            Reply text from backend
        """
        try:
            payload = {
                "user_id": str(user_id),
                "username": username,
                "message": message
            }
            
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                self._backend_url,
                data=data,
                headers={"Content-Type": "application/json"}
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result.get("reply", "No response from backend")
        
        except urllib.error.HTTPError as e:
            return f"Backend error: {e.code}"
        except Exception as e:
            return f"Connection failed: {str(e)[:100]}"

    def send_alert(self, text: str) -> bool:
        """Send alert message via HTTP API.
        
        Args:
            text: HTML-formatted message text
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.ready:
            return False
        
        return self._send_message(text)

    def send_clawnet_alert(
        self,
        level: str,
        process: str,
        pid: Optional[int] = None,
        remote: str = "",
        rport: object = "",
        geo: str = "",
        reason: str = "",
        action: str = "monitor",
    ) -> bool:
        """Send a formatted ClawNet intelligence alert."""
        normalized_level = (level or "").strip().upper()
        icon = "CRITICAL" if normalized_level == "CRITICAL" else "SUSPICIOUS"
        proc_text = _html_escape(process or "unknown")
        pid_text = _html_escape(str(pid if pid is not None else "-"))
        reason_text = _html_escape(reason or "ClawNet flagged this activity")
        action_text = _html_escape(action or "monitor")
        geo_text = _html_escape(geo or "-")

        remote_text = "-"
        if remote:
            remote_text = str(remote)
            if rport not in ("", None, "-"):
                remote_text = f"{remote_text}:{rport}"
        remote_text = _html_escape(remote_text)

        return self.send_alert(
            f"<b>ClawNet Intelligence: {icon}</b>\n"
            f"Process: <code>{proc_text}</code>  PID: <code>{pid_text}</code>\n"
            f"Remote: <code>{remote_text}</code>  ({geo_text})\n"
            f"Reason: {reason_text}\n"
            f"Suggested: <b>{action_text}</b>\n"
            f"Time: {time.strftime('%H:%M:%S')}"
        )

    def _send_message(self, text: str) -> bool:
        """Send message via Telegram HTTP API with retry."""
        if not self._base_url or not self._chat_id:
            self._status = "error: not-configured"
            return False
        
        url = f"{self._base_url}/sendMessage"
        payload = {
            "chat_id": self._chat_id,
            "text": text,
            "parse_mode": "HTML"
        }
        
        # Retry up to 3 times for transient failures
        for attempt in range(3):
            try:
                data = urllib.parse.urlencode(payload).encode('utf-8')
                req = urllib.request.Request(url, data=data)
                req.add_header('Content-Type', 'application/x-www-form-urlencoded')
                
                with urllib.request.urlopen(req, timeout=10) as response:
                    if response.status == 200:
                        self._status = "ready"
                        return True
                    else:
                        self._status = f"http-error: {response.status}"
                        return False
            
            except urllib.error.HTTPError as e:
                error_code = e.code
                
                # Permanent errors - don't retry
                if error_code in (400, 401, 404):
                    self._status = f"error: bad-config-{error_code}"
                    return False
                
                # Transient errors - retry
                if attempt < 2:
                    time.sleep(0.5 * (attempt + 1))  # 0.5s, 1s backoff
                    continue
                
                self._status = f"http-error: {error_code}"
                return False
            
            except (urllib.error.URLError, TimeoutError) as e:
                # Network error - retry
                if attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                self._status = f"network-error"
                return False
            
            except Exception as e:
                self._status = f"error: {str(e)[:50]}"
                return False
        
        return False

    def get_updates(self, offset: int = 0) -> list:
        """Fetch pending updates via HTTP API (polling).
        
        Args:
            offset: Update offset for polling
            
        Returns:
            List of update objects or empty list
        """
        if not self.available or not self._base_url:
            return []
        
        try:
            url = f"{self._base_url}/getUpdates"
            payload = {
                "offset": offset,
                "timeout": 5,
                "allowed_updates": ["message"]
            }
            
            data = urllib.parse.urlencode(payload).encode('utf-8')
            req = urllib.request.Request(url, data=data)
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            with urllib.request.urlopen(req, timeout=15) as response:
                result = json.loads(response.read().decode('utf-8'))
                
                if result.get("ok"):
                    return result.get("result", [])
                else:
                    self._status = f"api-error"
                    return []
        
        except Exception:
            return []

    def send_reply(self, message_id: int, text: str) -> bool:
        """Send a reply to a message.
        
        Args:
            message_id: Message ID to reply to
            text: HTML-formatted response text
            
        Returns:
            True if sent, False otherwise
        """
        if not self.ready or not self._base_url:
            return False
        
        try:
            url = f"{self._base_url}/sendMessage"
            payload = {
                "chat_id": self._chat_id,
                "text": text,
                "parse_mode": "HTML",
                "reply_to_message_id": message_id
            }
            
            data = urllib.parse.urlencode(payload).encode('utf-8')
            req = urllib.request.Request(url, data=data)
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status == 200
        
        except Exception:
            return False


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
    """Pick a weighted random severity and message."""
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
        """Start mock update scheduler."""
        if self._running:
            return
        self._running = True
        threading.Thread(target=self._loop, daemon=True, name="tg-mock").start()

    def stop(self) -> None:
        """Stop mock update scheduler."""
        self._running = False

    def _loop(self) -> None:
        """Main mock update loop."""
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
    """Update TELEGRAM_CHAT_ID in .env file."""
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
