#!/usr/bin/env python3
"""
osc_monitor.py - OSC listener for testing wavesnx_osc.py.

Prints every OSC message received on the given port, so the head-tracker output
can be checked without IEM/SPARTA/Virtuoso running.

    python osc_monitor.py            # listen on 127.0.0.1:8000
    python osc_monitor.py --port 9000
"""

import argparse
from pythonosc.dispatcher import Dispatcher
from pythonosc.osc_server import BlockingOSCUDPServer


def show(address, *args):
    vals = "  ".join(f"{a:+8.3f}" if isinstance(a, float) else str(a) for a in args)
    print(f"{address:<26} {vals}")


def main():
    ap = argparse.ArgumentParser(description="OSC monitor for wavesnx_osc.py")
    ap.add_argument("--ip", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    disp = Dispatcher()
    disp.set_default_handler(show)  # print every incoming message

    server = BlockingOSCUDPServer((args.ip, args.port), disp)
    print(f"[monitor] listening on {args.ip}:{args.port}  (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[monitor] stopped")


if __name__ == "__main__":
    main()
