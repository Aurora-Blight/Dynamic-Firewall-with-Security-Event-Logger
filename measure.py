#!/usr/bin/env python3
"""
measure.py - automated measurements (latency, throughput, new-connection time,
and optionally repeated block tests).  Needs iperf (v2) installed.

  # 1) baseline: controller = plain learning switch
  ryu-manager ryu.app.simple_switch_13
  sudo python3 measure.py --label baseline

  # 2) firewall (start logger_server.py too if you use --block-rounds)
  ryu-manager firewall.py
  sudo python3 measure.py --label firewall --block-rounds 10

Run 'sudo mn -c' and restart the controller between runs.
Block response times are written by the controller into events.log; run
analyze.py afterwards.
"""
import argparse
import os
import re
import time

from mininet.log import setLogLevel

import policy as P
from topo import HERE, build_net, start_server, wait_for_controller


def parse_ping(out):
    m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    loss = re.search(r"(\d+)% packet loss", out)
    if not m:
        return None
    return dict(min=float(m.group(1)), avg=float(m.group(2)), max=float(m.group(3)),
                mdev=float(m.group(4)), loss=int(loss.group(1)) if loss else None)


def parse_iperf(out):
    vals = re.findall(r"([\d.]+) Mbits/sec", out)
    return float(vals[-1]) if vals else None


def parse_connect_times(out):
    vals = [float(x) for x in re.findall(r"connected in ([\d.]+) ms", out)]
    return (sum(vals) / len(vals), len(vals)) if vals else (None, 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="run")
    ap.add_argument("--ping-count", type=int, default=50)
    ap.add_argument("--iperf-secs", type=int, default=10)
    ap.add_argument("--connect-count", type=int, default=30)
    ap.add_argument("--block-rounds", type=int, default=0,
                    help="repeat the flood->block->recover test N times (firewall only)")
    a = ap.parse_args()

    setLogLevel("warning")
    net = build_net()
    net.start()
    wait_for_controller(net)
    start_server(net)
    h1, h4 = net.get("h1", "h4")
    time.sleep(1)
    h1.cmd("ping -c 3 %s" % P.SERVER_IP)      # warm-up (ARP, first flows)

    lines = ["== results for '%s' ==" % a.label]

    ping = parse_ping(h1.cmd("ping -c %d -i 0.2 %s" % (a.ping_count, P.SERVER_IP)))
    if ping:
        lines.append("ping h1->h4: avg %.3f ms  min %.3f  max %.3f  mdev %.3f  loss %s%%" % (
            ping["avg"], ping["min"], ping["max"], ping["mdev"], ping["loss"]))
    else:
        lines.append("ping: could not parse output")

    h4.cmd("iperf -s > /tmp/iperf_server.log 2>&1 &")
    time.sleep(1)
    mbps = parse_iperf(h1.cmd("iperf -c %s -t %d -f m" % (P.SERVER_IP, a.iperf_secs)))
    h4.cmd("pkill iperf")
    lines.append("iperf h1->h4: %s Mbit/s" % (mbps if mbps is not None else "n/a (is iperf installed?)"))

    out = h1.cmd("python3 %s/client.py %s 8080 -n %d -d 0.3" % (HERE, P.SERVER_IP, a.connect_count))
    avg_c, n_c = parse_connect_times(out)
    lines.append("new TCP connection h1->h4:8080: avg connect time %s ms over %d connections" % (
        "%.3f" % avg_c if avg_c is not None else "n/a", n_c))

    for r in range(1, a.block_rounds + 1):
        h1.cmd("python3 %s/client.py %s %d -n 8 -d 0.2 -t 1" % (HERE, P.SERVER_IP, P.RESTRICTED_PORT))
        lines.append("block round %d/%d done" % (r, a.block_rounds))
        print(lines[-1], flush=True)
        time.sleep(P.BLOCK_SECS + 2)          # wait for automatic recovery

    h4.cmd("pkill -f server.py")
    net.stop()

    text = "\n".join(lines)
    print("\n" + text)
    with open(os.path.join(HERE, "results_%s.txt" % a.label), "w") as f:
        f.write(text + "\n")


if __name__ == "__main__":
    main()
