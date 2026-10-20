#!/usr/bin/env python3
"""server.py - multi-client TCP server (runs on h4).  One listener per port."""
import socket
import sys
import threading
import time

DEFAULT_PORTS = [8080, 8081, 9999]


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def handle(conn, addr, port):
    with conn:
        conn.settimeout(10)
        try:
            data = conn.recv(1024)
            log("port %d: %s:%d sent %r" % (port, addr[0], addr[1], data.decode(errors="replace").strip()))
            conn.sendall(("ACK from port %d: %s\n" % (port, data.decode(errors="replace").strip())).encode())
        except OSError:
            pass


def listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(128)
    log("listening on port %d" % port)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr, port), daemon=True).start()


def main():
    ports = [int(p) for p in sys.argv[1:]] or DEFAULT_PORTS
    for p in ports:
        threading.Thread(target=listener, args=(p,), daemon=True).start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
