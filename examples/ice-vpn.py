#!/usr/bin/env python3

import argparse
import asyncio
import datetime
import json
import logging
import ssl
import subprocess
import sys
import threading

import websockets

import aioice
import tuntap

STUN_SERVER = ("stun.l.google.com", 19302)


def print_exception_and_exit(loop, context):
    loop.stop()
    print("exception handler", context)
    exit(1)


def debug(*args) -> None:
    print(datetime.datetime.now().time().isoformat(), threading.current_thread().name, *args, file=sys.stderr)


def object_from_string(str):
    return json.loads(str)


def object_to_string(descr):
    return json.dumps(descr)


class SimpleWebsocketSignaling:
    def __init__(self, server, our_id, remote_id, request_offer: bool):
        self.server = server
        self.request_offer = request_offer
        self.our_id = our_id
        self.remote_id = remote_id
        self.wsconn = None

    async def connect(self):
        await self.websocket_connect()

    async def close(self):
        debug("SimpleWebsocketSignaling close")
        if self.wsconn is not None:
            await self.wsconn.close()
            self.wsconn = None

    async def receive(self):
        recv = await self.wsconn.recv()
        debug("<", recv)
        return object_from_string(recv)

    async def send(self, descr):
        await self.send_ws_msg(object_to_string(descr))

    async def websocket_connect(self):
        if self.server.startswith("wss://"):
            sslctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            self.wsconn = await websockets.connect(self.server, ssl=sslctx, ping_interval=5)
        else:
            self.wsconn = await websockets.connect(self.server, ping_interval=5)
        await self.send_ws_msg(f'HELLO {self.our_id}')
        msg = await self.wsconn.recv()
        if "HELLO" != msg:
            raise Exception("expected HELLO. got unhandled response " + msg)

        if self.request_offer:
            await self.send_ws_msg(f'SESSION {self.remote_id}')
            msg = await self.wsconn.recv()
            if 'SESSION_OK' == msg:
                await self.send_ws_msg(f'OFFER_REQUEST')
            else:
                raise Exception("expected SESSION_OK. got unhandled response " + msg)
        else:
            msg = await self.wsconn.recv()
            if 'OFFER_REQUEST' == msg:
                debug("offer requested")
            else:
                raise Exception("unhandled response " + msg)

    async def send_ws_msg(self, txt: str):
        debug(f'> {txt}')
        await self.wsconn.send(txt)


async def tun_start(tap, connection):
    debug("tun_start")
    tap.open()

    loop = asyncio.get_event_loop()

    # relay tap -> channel
    def tun_reader():
        data = tap.fd.read(tap.mtu + 32)
        # print("read", len(data))
        if data:
            loop.create_task(connection.sendto(data, component=1))

    loop.set_exception_handler(print_exception_and_exit)
    loop.add_reader(tap.fd, tun_reader)

    mtu = tap.mtu
    tap.up()
    debug("tun_start tap up", mtu, tap.name.decode())
    subprocess.run(["ip", "address", "add", tap.ip_addr, "dev", tap.name.decode()], check=True)
    subprocess.run(["ip", "link", "set", "dev", tap.name.decode(), "mtu", str(mtu)], check=True)
    tap.get_mtu()
    while True:
        data, component = await connection.recvfrom()
        if data:
            # print("write", len(data))
            tap.fd.write(data)


def make_connection(options):
    allow_interfaces = None
    if options.allow_iface:
        allow_interfaces = [options.allow_iface]
    controlling = options.action == "offer"
    connection = aioice.Connection(
        ice_controlling=controlling, components=options.components, stun_server=STUN_SERVER,
        use_ipv6=False,
        allow_interfaces=allow_interfaces
    )
    return connection


def make_signaling(options):
    return SimpleWebsocketSignaling(our_id=options.our_id, remote_id=options.remote_id,
                                    server=options.signaling_url,
                                    request_offer=options.action == "answer")


async def offer(options):
    connection = make_connection(options)
    await connection.gather_candidates()

    signaling = make_signaling(options)
    await signaling.connect()

    # send offer
    offer_ = {"candidates": [c.to_sdp() for c in connection.local_candidates], "password": connection.local_password,
              "username": connection.local_username, }
    await signaling.send(offer_)

    # await answer
    answer_ = await signaling.receive()
    for c in answer_["candidates"]:
        await connection.add_remote_candidate(aioice.Candidate.from_sdp(c))
    await connection.add_remote_candidate(None)
    connection.remote_username = answer_["username"]
    connection.remote_password = answer_["password"]

    await signaling.close()

    tap = tuntap.Tun(name=options.dev, ip_addr=options.ip, mtu=options.mtu)
    await connection.connect()
    debug("connected")

    await tun_start(tap, connection)


async def answer(options):
    connection = make_connection(options)
    await connection.gather_candidates()

    signaling = make_signaling(options)

    await signaling.connect()

    # await offer
    offer_ = await signaling.receive()
    for c in offer_["candidates"]:
        await connection.add_remote_candidate(aioice.Candidate.from_sdp(c))
    await connection.add_remote_candidate(None)
    connection.remote_username = offer_["username"]
    connection.remote_password = offer_["password"]

    # send answer
    answer_ = {"candidates": [c.to_sdp() for c in connection.local_candidates],
               "password": connection.local_password,
               "username": connection.local_username, }
    await signaling.send(answer_)
    await signaling.close()

    tap = tuntap.Tun(name=options.dev, ip_addr=options.ip, mtu=options.mtu)
    await connection.connect()
    debug("connected")

    await tun_start(tap, connection)


parser = argparse.ArgumentParser(description="ICE tester")
parser.add_argument("action", choices=["offer", "answer"])
parser.add_argument("--components", type=int, default=1)
parser.add_argument("--allow-iface", default=None)
parser.add_argument("--dev", type=str)
parser.add_argument("--ip", type=str)
parser.add_argument("--mtu", type=int)
parser.add_argument("--signaling-url", default="", help="Signaling url (eg wss://server:443)")
parser.add_argument("--our-id", default="", help="Signaling id of this host (websocket only)")
parser.add_argument("--remote-id", default="", help="Signaling id of remote host to connect to (websocket only)")
options = parser.parse_args()

logging.basicConfig(level=logging.DEBUG)
loop = asyncio.get_event_loop()

if options.action == "offer":
    loop.run_until_complete(offer(options))
    loop.run_forever()
else:
    loop.run_until_complete(answer(options))
    loop.run_forever()
