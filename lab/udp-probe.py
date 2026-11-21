"""Finite UDP sample between named lab endpoints. The receiver uses a private ephemeral port."""
import json
import socket
import sys
import time


COUNT = 24
action, address, token = sys.argv[1:4]
prefix = token.encode("ascii") + b"/"
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    if action == "send":
        destination = (address, int(sys.argv[4]))
        for seq in range(COUNT):
            sock.sendto(prefix + bytes([seq]), destination)
            time.sleep(0.06)
    elif action == "receive":
        sock.bind((address, 0))
        print("READY", sock.getsockname()[1], flush=True)
        end = time.monotonic() + 5
        seen, sources = set(), set()
        duplicates = reordered = 0
        highest = -1
        while time.monotonic() < end:
            sock.settimeout(max(0.001, end - time.monotonic()))
            try:
                data, peer = sock.recvfrom(256)
            except socket.timeout:
                break
            if len(data) != len(prefix) + 1 or not data.startswith(prefix):
                continue
            seq = data[-1]
            if seq >= COUNT:
                continue
            sources.add(peer[0])
            if seq in seen:
                duplicates += 1
            else:
                seen.add(seq)
                reordered += int(seq < highest)
                highest = max(highest, seq)
        print(json.dumps(dict(sent=COUNT, received=len(seen), duplicates=duplicates,
                              reordered=reordered, sources=sorted(sources))))
    else:
        raise SystemExit("unknown probe action")
