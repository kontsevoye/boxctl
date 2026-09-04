#!/usr/bin/env python3
"""Disable the preparation NIC at the host-owned QEMU boundary."""

import json
import socket
import sys


if len(sys.argv) != 3:
    raise SystemExit("usage: qmp-link-down.py SOCKET DEVICE_ID")

socket_path, device_id = sys.argv[1:]
if not device_id.replace("-", "").replace("_", "").isalnum():
    raise SystemExit("invalid device id")

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5)
client.connect(socket_path)
stream = client.makefile("rwb", buffering=0)


def receive():
    message = stream.readline()
    if not message:
        raise RuntimeError("QMP socket closed")
    return json.loads(message)


def send(command):
    stream.write(json.dumps(command, separators=(",", ":")).encode() + b"\r\n")


try:
    if "QMP" not in receive():
        raise RuntimeError("missing QMP greeting")
    send({"execute": "qmp_capabilities", "id": "capabilities"})
    while receive().get("id") != "capabilities":
        pass
    send({"execute": "set_link", "arguments": {"name": device_id, "up": False}, "id": "link-down"})
    while True:
        response = receive()
        if response.get("id") == "link-down":
            if "error" in response:
                raise RuntimeError(str(response["error"]))
            break
finally:
    client.close()
