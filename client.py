#!/usr/bin/env python3
"""
client.py - TCP client.  Makes N connection attempts to dst:port.

  python3 client.py 10.0.0.4 8080              # one normal request
  python3 client.py 10.0.0.4 9999 -n 8 -d 0.2  # flood the restricted port
"""
import argparse
import socket
import time


def attempt(dst, port, timeout, i):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t = time.time()
    try:
        s.connect((dst, port))
        connect_ms = (time.time() - t) * 1000.0
        s.sendall(("hello %d\n" % i).encode())
        reply = s.recv(1024).decode(errors="replace").strip()
        return True, "OK       connected in %.1f ms, reply: %s" % (connect_ms, reply)
    except socket.timeout:
        return False, "TIMEOUT  (no answer - SYN dropped: denied or blocked?)"
    except ConnectionRefusedError:
        return False, "REFUSED  (nothing listening on that port)"
    except OSError as e:
        return False, "ERROR    %s" % e
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dst")
    ap.add_argument("port", type=int)
    ap.add_argument("-n", "--count", type=int, default=1, help="number of attempts")
    ap.add_argument("-d", "--delay", type=float, default=0.5, help="seconds between attempts")
    ap.add_argument("-t", "--timeout", type=float, default=2.0, help="connect timeout (s)")
    a = ap.parse_args()

    ok = 0
    for i in range(1, a.count + 1):
        success, text = attempt(a.dst, a.port, a.timeout, i)
        ok += success
        print("[%s] attempt %d/%d -> %s:%d  %s" % (
            time.strftime("%H:%M:%S"), i, a.count, a.dst, a.port, text), flush=True)
        if i < a.count:
            time.sleep(a.delay)
    print("summary: %d/%d succeeded" % (ok, a.count))


if __name__ == "__main__":
    main()
