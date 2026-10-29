# Dynamic Firewall with Security Event Logger

An **SDN-based dynamic firewall** built on [Ryu](https://ryu-sdn.org/) and [Mininet](http://mininet.org/). It enforces per-connection TCP policy on an OpenFlow 1.3 switch, rate-limits repeated connection attempts to a restricted port, auto-blocks offending hosts, and ships every security event as a JSON line to a centralised logging server.

---

## Architecture

```
┌──────────────────────────────────────┐
│  Mininet (topo.py)                   │
│                                      │
│  h1 (10.0.0.1) ─┐                   │
│  h2 (10.0.0.2) ─┤── s1 (OVS) ───── h4 (10.0.0.4)  ← server.py │
│  h3 (10.0.0.3) ─┘   │               │
│                      │ OpenFlow 1.3  │
└──────────────────────┼───────────────┘
                       │
          ┌────────────▼────────────┐
          │  Ryu controller         │
          │  firewall.py            │
          │  policy.py              │
          └────────────┬────────────┘
                       │ TCP JSON events (port 5000)
          ┌────────────▼────────────┐
          │  logger_server.py       │
          │  → events.log           │
          └─────────────────────────┘
```

| File | Role |
|---|---|
| `firewall.py` | Ryu controller app — packet-in handler, flow installer, block/unblock logic |
| `policy.py` | Pure-Python policy rules, attempt tracker, tunable constants |
| `topo.py` | Mininet topology (1 switch, h1–h3 clients, h4 server) |
| `server.py` | Simple TCP echo server running on h4 (ports 8080, 8081, 9999) |
| `client.py` | TCP test client to send traffic from a Mininet host |
| `logger_server.py` | Centralised event receiver — writes `events.log` |
| `analyze.py` | Post-run log analyser: event counts, response-time stats, block duration |
| `measure.py` | Automated traffic measurement script (iperf / repeated connections) |

---

## How It Works

1. **Table-miss rule** sends every unknown packet to the Ryu controller.
2. **Non-TCP traffic** (ARP, ICMP, …) is forwarded by a plain L2 learning switch.
3. **Every new TCP connection** triggers a packet-in. The controller checks `policy.py` and installs an *allow* or *drop* flow for that exact 5-tuple.
4. **Rate-limiting**: SYN packets to `RESTRICTED_PORT` (default **9999**) are counted per source IP in a sliding window. Exceeding `MAX_ATTEMPTS` (5) within `WINDOW_SECS` (10 s) installs a high-priority drop rule for that host.
5. **Auto-recovery**: after `BLOCK_SECS` (30 s) the block rule is removed and the attempt counter is reset.
6. **Every event** (ALLOW / DENY / BLOCK / UNBLOCK) is queued off the packet-in path and sent as a JSON line to `logger_server.py` over TCP on port 5000.

### Default Policy (edit `policy.py` to change)

| Source | Destination | Port | Action |
|---|---|---|---|
| 10.0.0.3 | 10.0.0.4 | 8080 | **DENY** (source-based rule) |
| any | 10.0.0.4 | 8080 | ALLOW |
| any | 10.0.0.4 | 8081 | **DENY** (port-based rule) |
| any | 10.0.0.4 | 9999 | ALLOW (rate-monitored) |
| any | any | 5001 | ALLOW (iperf) |
| *(no match)* | | | **DENY** (default-deny) |

---

## Requirements

- **Linux** (Mininet requires a Linux kernel)
- **Python 3.8+**
- [Mininet](http://mininet.org/download/) (`sudo apt install mininet`)
- [Open vSwitch](https://www.openvswitch.org/) (`sudo apt install openvswitch-switch`)
- [Ryu SDN Framework](https://github.com/faucetsdn/ryu) — install in a virtual environment (see below)

```bash
# Install system dependencies
sudo apt update
sudo apt install -y mininet openvswitch-switch python3-pip python3-venv

# Create a virtualenv for Ryu (Ryu requires Python 3 and specific eventlet versions)
python3 -m venv ryu-env
source ryu-env/bin/activate
pip install ryu eventlet==0.30.2
```

> **Note:** Mininet must be run with the *system* Python (`sudo python3`), **not** inside the Ryu virtualenv. Keep two terminals — one for each.

---

## Running the Project

You need **three terminal windows**, all opened in the project directory.

### Terminal 1 — Logger Server

```bash
python3 logger_server.py
# Optional: specify a custom log file
python3 logger_server.py my_events.log
```

The logger listens on `127.0.0.1:5000` and writes every event to `events.log`.

---

### Terminal 2 — Ryu Controller

```bash
source ryu-env/bin/activate
ryu-manager firewall.py
```

The controller connects to Open vSwitch on port **6653** (OpenFlow 1.3). Keep this running — it will print ALLOW/DENY/BLOCK/UNBLOCK lines as traffic flows.

---

### Terminal 3 — Mininet Topology

```bash
sudo python3 topo.py
```

This starts the virtual network with one switch (`s1`) and four hosts (`h1`–`h4`). The server (`server.py`) starts automatically on `h4`. You'll land in the **Mininet CLI**.

---

## Testing Traffic in the Mininet CLI

Once the Mininet CLI is open (`mininet>`), try the following:

```bash
# Allowed connection: h1 → h4:8080
mininet> h1 python3 client.py 10.0.0.4 8080

# Denied by source rule: h3 → h4:8080
mininet> h3 python3 client.py 10.0.0.4 8080

# Denied by port rule: h1 → h4:8081
mininet> h1 python3 client.py 10.0.0.4 8081

# Rate-monitored port — trigger auto-block by connecting rapidly
mininet> h2 python3 client.py 10.0.0.4 9999
# Repeat 6+ times within 10 seconds to see h2 get blocked

# Basic connectivity test
mininet> pingall
```

---

## Analysing the Log

After running some traffic, analyse `events.log`:

```bash
python3 analyze.py
# Or specify a custom log file:
python3 analyze.py my_events.log
```

Sample output:
```
events in events.log: 42
  ALLOW    28
  BLOCK    3
  DENY     8
  UNBLOCK  3

BLOCK response time (controller, packet-in -> flow-mod queued), n=3
  avg 1.234 ms  min 0.987  max 1.541  stdev 0.231

block duration until recovery (s): avg 30.21 min 30.11 max 30.34 n=3
```

---

## Configuration

All tuneable constants live in `policy.py`:

| Constant | Default | Description |
|---|---|---|
| `SERVER_IP` | `10.0.0.4` | IP of the server host (h4) |
| `RESTRICTED_PORT` | `9999` | Port monitored for brute-force attempts |
| `MAX_ATTEMPTS` | `5` | Max SYN packets before blocking |
| `WINDOW_SECS` | `10` | Sliding window for attempt counting (seconds) |
| `BLOCK_SECS` | `30` | How long a blocked host stays blocked (seconds) |
| `LOGGER_ADDR` | `("127.0.0.1", 5000)` | Address of the logger server |
| `POLICY` | see file | List of `(src_ip, dst_ip, dst_port, action)` rules |
| `DEFAULT_ACTION` | `"deny"` | Default firewall action when no rule matches |

To add a rule, prepend a tuple to the `POLICY` list. `None` acts as a wildcard:
```python
# Allow h1 to reach port 7777
("10.0.0.1", SERVER_IP, 7777, "allow"),
```

---

## Event Log Format

Each event written to `events.log` is a JSON line:

```json
{
  "time": "2026-10-29 14:05:22",
  "ts": 1730207122.123456,
  "event": "BLOCK",
  "src": "10.0.0.2",
  "dst": "10.0.0.4",
  "port": 9999,
  "reason": ">5 attempts to port 9999 within 10s -> blocked for 30s",
  "response_ms": 1.234
}
```

`event` is one of: `ALLOW`, `DENY`, `BLOCK`, `UNBLOCK`.  
`response_ms` is the controller-side processing time from packet-in to flow-mod being queued (present on ALLOW, DENY, BLOCK events).

---

## License

MIT — see [LICENSE](LICENSE).
