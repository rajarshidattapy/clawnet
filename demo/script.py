"""ClawForge demo target: a harmless process that ClawNet's policy engine flags.

It opens one HTTPS connection to example.com and holds it open so the network
monitor and the agent can see it. It reads nothing, writes nothing, and hides nothing.

Why it gets flagged anyway: ClawNet scores the *process*, and this process is
python.exe from the project's .venv under \\Desktop\\ (a drop zone), talking to a
foreign IP, launched from a shell. The verdict comes from where it runs, not
from what this code does.

    python demo/script.py            # hold for 10 minutes
    python demo/script.py 120        # hold for 120 seconds

Then ask ClawForge (console or /watch):
    "Which processes look suspicious right now? Explain the worst one."
"""
import os
import socket
import ssl
import sys
import time

HOST = "example.com"
HOLD = int(sys.argv[1]) if len(sys.argv) > 1 else 600

ctx = ssl.create_default_context()
with socket.create_connection((HOST, 443), timeout=10) as raw:
    with ctx.wrap_socket(raw, server_hostname=HOST) as conn:
        peer = conn.getpeername()[0]
        print(f"PID {os.getpid()}  ->  {HOST} ({peer}:443)  holding for {HOLD}s  (Ctrl+C to stop)")
        deadline = time.time() + HOLD
        try:
            while time.time() < deadline:
                # A tiny HEAD request every 20s keeps the connection ESTABLISHED.
                conn.sendall(f"HEAD / HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode())
                conn.recv(4096)
                time.sleep(20)
        except (KeyboardInterrupt, OSError):
            pass
print("closed")
