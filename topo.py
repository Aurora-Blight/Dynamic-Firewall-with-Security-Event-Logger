#!/usr/bin/env python3
"""
topo.py - Mininet topology: one OpenFlow 1.3 switch, h1-h3 clients, h4 server.

Run from this folder (system python, not the Ryu venv):
    sudo python3 topo.py
"""
import os

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

HERE = os.path.dirname(os.path.abspath(__file__))


def build_net():
    net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=True)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    for i in range(1, 5):                       # h1..h4 = 10.0.0.1 .. 10.0.0.4
        h = net.addHost("h%d" % i, ip="10.0.0.%d/24" % i)
        net.addLink(h, s1)
    return net


def start_server(net):
    net.get("h4").cmd("python3 %s/server.py > /tmp/server.log 2>&1 &" % HERE)


def wait_for_controller(net):
    try:
        ok = net.waitConnected(timeout=15)
    except TypeError:
        ok = True
    if not ok:
        info("*** WARNING: switch did not connect to the controller. "
             "Is ryu-manager running?\n")


if __name__ == "__main__":
    setLogLevel("info")
    net = build_net()
    net.start()
    wait_for_controller(net)
    start_server(net)
    info("*** Server running on h4 (10.0.0.4) ports 8080 8081 9999\n")
    info("*** Try:  h1 python3 client.py 10.0.0.4 8080\n")
    CLI(net)
    net.get("h4").cmd("pkill -f server.py")
    net.stop()
