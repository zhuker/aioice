#!/usr/bin/env python3

import argparse
import asyncio
import datetime
import logging
import sys
import threading

import aioice

STUN_SERVER = ("stun.l.google.com", 19302)


def debug(*args) -> None:
    print(datetime.datetime.now().time().isoformat(), threading.current_thread().name, *args, file=sys.stderr)


def make_connection(options):
    allow_interfaces = None
    if options.allow_iface:
        allow_interfaces = [options.allow_iface]
    controlling = options.action == "offer"
    connection = aioice.Connection(
        ice_controlling=controlling, components=options.components, stun_server=STUN_SERVER,
        use_ipv6=options.ipv6,
        allow_interfaces=allow_interfaces
    )
    return connection


async def candidates(options):
    connection = make_connection(options)
    await connection.gather_candidates(timeout=10)
    for c in connection.local_candidates:
        debug(c)


parser = argparse.ArgumentParser(description="ICE tester")
parser.add_argument("action", choices=["offer", "answer"])
parser.add_argument("--components", type=int, default=1)
parser.add_argument("--allow-iface", default=None)
parser.add_argument("--dev", type=str)
parser.add_argument("--ipv6", action='store_true')
options = parser.parse_args()

logging.basicConfig(level=logging.DEBUG)
loop = asyncio.get_event_loop()

loop.run_until_complete(candidates(options))
