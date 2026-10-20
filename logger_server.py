#!/usr/bin/env python3
"""
logger_server.py - centralized security-event logger.

Receives newline-delimited JSON events from the Ryu controller over TCP,
prints them and appends them to events.log.

  python3 logger_server.py [logfile]
"""
import json
import socket
import sys
import threading

HOST, PORT = "0.0.0.0", 5000
LOGFILE = sys.argv[1] if len(sys.argv) > 1 else "events.log"
lock = threading.Lock()


def pretty(evt):
    extra = ""
    if "response_ms" in evt:
        extra = "  [%.3f ms]" % evt["response_ms"]
    dst = "%s:%s" % (evt.get("dst"), evt.get("port")) if evt.get("dst") else "-"
    return "%s  %-7s %s -> %s  %s%s" % (
        evt.get("time", "?"), evt.get("event", "?"), evt.get("src"), dst,
        evt.get("reason", ""), extra)


def handle(conn, addr):
    with conn, conn.makefile("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            with lock:
                with open(LOGFILE, "a") as out:
                    out.write(line + "\n")
                try:
                    print(pretty(json.loads(line)), flush=True)
                except ValueError:
                    print("RAW", line, flush=True)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(16)
    print("logger listening on %s:%d, writing to %s" % (HOST, PORT, LOGFILE), flush=True)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
