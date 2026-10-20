"""
policy.py - firewall configuration and pure logic (no Ryu imports, so it can be
unit-tested anywhere).

Edit the constants below to change the demo.
"""
import time
from collections import defaultdict, deque

# ---------------------------------------------------------------- settings
SERVER_IP = "10.0.0.4"          # h4 runs server.py
RESTRICTED_PORT = 9999          # repeated attempts here trigger auto-block
MAX_ATTEMPTS = 5                # more than this many ...
WINDOW_SECS = 10                # ... within this many seconds -> block
BLOCK_SECS = 30                 # block duration before automatic recovery
LOGGER_ADDR = ("127.0.0.1", 5000)   # logger_server.py (runs next to the controller)

# Ports that belong to services (used to recognise server->client return traffic)
SERVICE_PORTS = {8080, 8081, 9999, 5001}

# First matching rule wins.  None = wildcard.
# (src_ip, dst_ip, dst_port, action)
POLICY = [
    ("10.0.0.3", SERVER_IP, 8080, "deny"),    # source-based example: h3 may not use 8080
    (None, SERVER_IP, 8080, "allow"),
    (None, SERVER_IP, 8081, "deny"),          # port-based example
    (None, SERVER_IP, RESTRICTED_PORT, "allow"),  # allowed, but rate-monitored
    (None, None, 5001, "allow"),              # iperf (measurements)
]
DEFAULT_ACTION = "deny"                       # default-deny firewall


def classify(src_ip, dst_ip, dst_port):
    """Return (action, reason) for a new TCP flow."""
    for r_src, r_dst, r_port, action in POLICY:
        if r_src not in (None, src_ip):
            continue
        if r_dst not in (None, dst_ip):
            continue
        if r_port not in (None, dst_port):
            continue
        return action, "policy rule (%s, %s, %s) -> %s" % (
            r_src or "*", r_dst or "*", r_port or "*", action)
    return DEFAULT_ACTION, "no matching rule, default %s" % DEFAULT_ACTION


def is_return_traffic(src_ip, src_port, dst_port):
    """Server -> client packets of an already-allowed connection."""
    return (src_ip == SERVER_IP
            and src_port in SERVICE_PORTS
            and dst_port not in SERVICE_PORTS)


class AttemptTracker:
    """Sliding-window counter of connection attempts per host."""

    def __init__(self, max_attempts=MAX_ATTEMPTS, window=WINDOW_SECS):
        self.max_attempts = max_attempts
        self.window = window
        self._hits = defaultdict(deque)

    def record(self, host, now=None):
        """Record one attempt. Returns True if the host exceeded the limit."""
        now = time.monotonic() if now is None else now
        q = self._hits[host]
        q.append(now)
        while q and now - q[0] > self.window:
            q.popleft()
        return len(q) > self.max_attempts

    def count(self, host):
        return len(self._hits.get(host, ()))

    def reset(self, host):
        self._hits.pop(host, None)
