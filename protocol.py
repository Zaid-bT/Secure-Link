"""
protocol.py  -- shared by server and clients (both members use this file unchanged).

Wire format: every message is  [4-byte big-endian length][UTF-8 JSON body].
TCP is a byte STREAM (no message boundaries), so we must frame messages ourselves.

JSON body always has: {"type": str, "from": str, "to": str, "data": any}
  to = "*"  -> broadcast to everybody (group chat)
  to = name -> unicast to that user

Message types:
  register    client -> server   data = {"pubkey": b64, "role": "user"|"sniffer"}
  register_ok server -> client   data = {}
  error       server -> client   data = "reason"
  user_list   server -> clients  data = [{"username":..., "pubkey":...}, ...]  (join order)
  dm          client -> client   data = Fernet token (str)
  group       client -> all      data = {"ver": int, "token": Fernet token}
  group_key   client -> client   data = Fernet token (str) of {"ver","key"}, encrypted with the DM key
  file_chunk  client -> client   data = Fernet token (str)
"""
import json
import struct

MAX_MSG = 4 * 1024 * 1024  # refuse absurdly large(>4MB)


def send_msg(sock, msg: dict):
    body = json.dumps(msg).encode("utf-8") #turns dict to JSON string, then encodes it to bytes, sockets only accept bytes
    sock.sendall(struct.pack(">I", len(body)) + body) #>=big-endian , I=unsigned int


def _recv_exact(sock, n: int):
    buf = b"" #buf:collects bytes until n bytes
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None #connection closed
        buf += chunk
    return buf


def recv_msg(sock):
    """Return a dict, or None if the peer closed the connection."""
    header = _recv_exact(sock, 4)
    if header is None:
        return None #connection closed 
    (length,) = struct.unpack(">I", header) #get number of bytes
    if length > MAX_MSG:
        raise ValueError("frame too large")
    body = _recv_exact(sock, length)
    if body is None:
        return None #connection closed midway
    return json.loads(body.decode("utf-8")) #decode bbytes to string, then parse JSON string to dict
