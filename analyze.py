#!/usr/bin/env python3
"""analyze.py - summarise events.log (event counts and blocking response time)."""
import json
import statistics
import sys
from collections import Counter

path = sys.argv[1] if len(sys.argv) > 1 else "events.log"
events = []
with open(path) as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except ValueError:
                pass

print("events in %s: %d" % (path, len(events)))
for name, n in sorted(Counter(e["event"] for e in events).items()):
    print("  %-8s %d" % (name, n))

for kind in ("BLOCK", "ALLOW", "DENY"):
    vals = [e["response_ms"] for e in events if e["event"] == kind and "response_ms" in e]
    if vals:
        print("\n%s response time (controller, packet-in -> flow-mod queued), n=%d" % (kind, len(vals)))
        print("  avg %.3f ms   min %.3f   max %.3f   stdev %.3f" % (
            statistics.mean(vals), min(vals), max(vals),
            statistics.stdev(vals) if len(vals) > 1 else 0.0))

# recovery time: BLOCK -> following UNBLOCK for the same host
pending, rec = {}, []
for e in events:
    if e["event"] == "BLOCK":
        pending[e["src"]] = e["ts"]
    elif e["event"] == "UNBLOCK" and e["src"] in pending:
        rec.append(e["ts"] - pending.pop(e["src"]))
if rec:
    print("\nblock duration until recovery (s): avg %.2f  min %.2f  max %.2f  n=%d" % (
        statistics.mean(rec), min(rec), max(rec), len(rec)))
