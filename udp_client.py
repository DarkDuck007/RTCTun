import argparse
import json
import os
import socket
import sys
import threading
import time

STUN_DEFAULT = "stun.l.google.com:19302"


def parse_host_port(value, default_port=None):
    if ":" not in value:
        if default_port is None:
            raise ValueError("Expected host:port")
        return value, default_port
    host, port = value.rsplit(":", 1)
    return host, int(port)


def get_local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except OSError:
            return "0.0.0.0"


def stun_binding_request(sock, stun_addr, timeout=2.0):
    transaction_id = os.urandom(12)
    cookie = 0x2112A442
    message_type = 0x0001
    message_length = 0
    header = (
        message_type.to_bytes(2, "big")
        + message_length.to_bytes(2, "big")
        + cookie.to_bytes(4, "big")
        + transaction_id
    )

    sock.settimeout(timeout)
    sock.sendto(header, stun_addr)
    data, _ = sock.recvfrom(2048)
    if len(data) < 20:
        return None

    msg_type = int.from_bytes(data[0:2], "big")
    if msg_type != 0x0101:
        return None

    msg_len = int.from_bytes(data[2:4], "big")
    trans_id = data[8:20]
    if trans_id != transaction_id:
        return None

    attrs = data[20:20 + msg_len]
    i = 0
    while i + 4 <= len(attrs):
        attr_type = int.from_bytes(attrs[i:i + 2], "big")
        attr_len = int.from_bytes(attrs[i + 2:i + 4], "big")
        value = attrs[i + 4:i + 4 + attr_len]
        padded = (attr_len + 3) & ~3
        if attr_type in (0x0020, 0x0001) and len(value) >= 8:
            family = value[1]
            if family == 0x01:
                if attr_type == 0x0020:
                    port = int.from_bytes(value[2:4], "big") ^ (cookie >> 16)
                    raw_ip = int.from_bytes(value[4:8], "big") ^ cookie
                    ip = ".".join(str((raw_ip >> shift) & 0xFF) for shift in (24, 16, 8, 0))
                else:
                    port = int.from_bytes(value[2:4], "big")
                    ip = ".".join(str(b) for b in value[4:8])
                return ip, port
        i += 4 + padded
    return None


def build_offer(sock, stun_hostport):
    local_ip = get_local_ip()
    local_port = sock.getsockname()[1]
    candidates = [
        {"ip": local_ip, "port": local_port, "type": "host"},
    ]

    try:
        host, port = parse_host_port(stun_hostport, 19302)
        mapped = stun_binding_request(sock, (host, port))
        if mapped:
            candidates.append({"ip": mapped[0], "port": mapped[1], "type": "srflx"})
    except (OSError, ValueError):
        pass

    return {
        "candidates": candidates,
    }


def parse_peer_offer(text):
    data = json.loads(text)
    candidates = data.get("candidates", [])
    result = []
    for cand in candidates:
        ip = cand.get("ip")
        port = cand.get("port")
        if ip and port:
            result.append((ip, int(port)))
    return result


def receiver_loop(sock, state):
    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except OSError:
            return
        text = data.decode("utf-8", errors="ignore")
        if text.startswith("PING"):
            sock.sendto(b"PONG", addr)
            state["connected"] = True
            state["peer"] = addr
            continue
        if text.startswith("PONG"):
            state["connected"] = True
            state["peer"] = addr
            continue
        if text:
            state["connected"] = True
            state["peer"] = addr
            print(f"Peer: {text}")


def punch_loop(sock, candidates, state, duration=10.0):
    deadline = time.time() + duration
    while time.time() < deadline and not state.get("connected"):
        for cand in candidates:
            sock.sendto(b"PING", cand)
        time.sleep(0.5)


def stdin_loop(sock, state):
    for line in sys.stdin:
        msg = line.rstrip("\n")
        if not msg:
            continue
        peer = state.get("peer")
        if not peer:
            print("No peer yet. Wait for connection.")
            continue
        sock.sendto(msg.encode("utf-8"), peer)


def main():
    parser = argparse.ArgumentParser(description="UDP peer client with manual signaling")
    parser.add_argument("--listen", type=int, default=50000)
    parser.add_argument("--stun", type=str, default=STUN_DEFAULT)
    parser.add_argument("--peer", type=str, default=None)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", args.listen))

    offer = build_offer(sock, args.stun)
    print("Offer (copy to peer):")
    print(json.dumps(offer, separators=(",", ":")))

    if not args.peer:
        print("Paste peer offer JSON and press Enter:")
        peer_text = sys.stdin.readline().strip()
    else:
        peer_text = args.peer

    candidates = parse_peer_offer(peer_text)
    if not candidates:
        print("No peer candidates provided.")
        return

    state = {"connected": False, "peer": None}

    recv_thread = threading.Thread(target=receiver_loop, args=(sock, state), daemon=True)
    recv_thread.start()

    punch_loop(sock, candidates, state)
    if state.get("connected"):
        print(f"Connected to {state['peer']}")
    else:
        print("No connection yet. Continuing to listen; try sending messages anyway.")

    stdin_loop(sock, state)


if __name__ == "__main__":
    main()
