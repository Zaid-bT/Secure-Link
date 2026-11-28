"""
client.py -- F2 (commands), F3 (keys), F4 (DM), F5 (group), F7 (tamper detect),
             F8 (fingerprint), F9 (file transfer), F10 (group key rotation).

Usage:  python client.py <username> [host] [port]
Commands:  <text>              group message (encrypted with group key)
           /dm <user> <msg>    end-to-end encrypted private message
           /users              list online users
           /fingerprint [user] show key fingerprint(s)
           /send <user> <file> encrypted file transfer
           /quit
"""
import base64
import json
import os
import socket
import sys
import threading
import time
import uuid

from cryptography.fernet import Fernet

from crypto_utils import (decrypt, derive_dm_fernet, encrypt, fingerprint,
                          generate_keypair)
from protocol import recv_msg, send_msg

TTL = 300            # reject Fernet tokens older than 5 min (replay protection, F7)
CHUNK = 32 * 1024    # file chunk size (bytes)


class Client:
    def __init__(self, name, host="127.0.0.1", port=5000, quiet=False, on_event=None):
        self.name, self.quiet = name, quiet
        self.on_event = on_event                          # GUI hook: on_event(kind, **data)
        self.sock = socket.create_connection((host, port))
        self.priv, self.pub = generate_keypair()          # F3: private key stays in memory only
        self.users = []                                   # [{"username","pubkey"}] in join order
        self.dm_cache = {}                                # pubkey -> Fernet
        self.group_keys = {}                              # version -> Fernet
        self.cur_ver = 0
        self.pending = []                                 # group msgs waiting for a key
        self.files = {}                                   # transfer id -> partial file
        self.inbox = []                                   # every line printed (used by tests)
        self.wlock = threading.Lock()
        self.slock = threading.RLock()
        self.running = True
        self._send("register", "server", {"pubkey": self.pub, "role": "user"})
        reply = recv_msg(self.sock)
        if not reply or reply["type"] != "register_ok":
            raise SystemExit(f"Registration failed: {reply and reply.get('data')}")
        threading.Thread(target=self._recv_loop, daemon=True).start()

    # ---------- helpers ----------
    def out(self, text):
        self.inbox.append(text)
        if not self.quiet:
            print(text, flush=True)

    def emit(self, kind, **kw):
        if self.on_event:
            self.on_event(kind, **kw)

    def warn(self, text, scope="system", peer=None):
        self.out(f"[!] {text}")
        self.emit("warning", text=text, scope=scope, peer=peer)

    def _send(self, mtype, to, data):
        with self.wlock:
            send_msg(self.sock, {"type": mtype, "from": self.name, "to": to, "data": data})

    def pubkey_of(self, user):
        with self.slock:
            for u in self.users:
                if u["username"] == user:
                    return u["pubkey"]
        return None

    def dm_key(self, user, wait=False):
        for _ in range(15 if wait else 1):                # user list may lag behind a message
            pk = self.pubkey_of(user)
            if pk:
                if pk not in self.dm_cache:
                    self.dm_cache[pk] = derive_dm_fernet(self.priv, pk)   # F4
                return self.dm_cache[pk]
            time.sleep(0.2)
        return None

    # ---------- receive side ----------
    def _recv_loop(self):
        try:
            while self.running:
                msg = recv_msg(self.sock)
                if msg is None:
                    break
                t = msg["type"]
                if t == "user_list":
                    self.on_user_list(msg["data"])
                elif t == "dm":
                    self.on_dm(msg)
                elif t == "group":
                    self.on_group(msg)
                elif t == "group_key":
                    self.on_group_key(msg)
                elif t == "file_chunk":
                    self.on_file_chunk(msg)
                elif t == "error":
                    self.out(f"[server] {msg['data']}")
                    self.emit("warning", text=f"Server: {msg['data']}", scope="system", peer=None)
        except (OSError, ValueError):
            pass
        if self.running:
            self.out("[!] disconnected from server")
            self.emit("disconnected")

    def on_user_list(self, users):
        with self.slock:
            old = {u["username"] for u in self.users}
            self.users = users
            new = {u["username"] for u in users}
        for n in sorted(new - old - {self.name}):
            self.out(f"[+] {n} joined")
            self.emit("system", text=f"{n} joined the chat")
        for n in sorted(old - new):
            self.out(f"[-] {n} left")
            self.emit("system", text=f"{n} left the chat")
        self.emit("users", users=users)
        # F10: the OLDEST member rotates the group key on every join/leave
        if new != old and users and users[0]["username"] == self.name:
            self.rotate_group_key()

    def rotate_group_key(self):
        with self.slock:
            ver = self.cur_ver + 1
            key = Fernet.generate_key()
            self.group_keys[ver] = Fernet(key)
            self.cur_ver = ver
            members = [u["username"] for u in self.users if u["username"] != self.name]
        payload = json.dumps({"ver": ver, "key": key.decode()}).encode()
        for m in members:                                  # each copy encrypted with that member's DM key
            f = self.dm_key(m)
            if f:
                self._send("group_key", m, encrypt(f, payload))
        self.out(f"[*] group key rotated -> v{ver}, sent to {len(members)} member(s)")
        self.emit("key", ver=ver, text=f"Group key rotated to v{ver} and sent to {len(members)} member(s)")

    def on_group_key(self, msg):
        f = self.dm_key(msg["from"], wait=True)
        raw = f and decrypt(f, msg["data"], TTL)
        if raw is None:
            self.warn(f"WARNING: bad group key from {msg['from']} (ignored)")
            return
        d = json.loads(raw)
        with self.slock:
            self.group_keys[d["ver"]] = Fernet(d["key"].encode())
            self.cur_ver = max(self.cur_ver, d["ver"])
            waiting, self.pending = self.pending, []
        self.out(f"[*] received group key v{d['ver']} from {msg['from']}")
        self.emit("key", ver=d["ver"], text=f"Received group key v{d['ver']} from {msg['from']}")
        for m in waiting:
            self.on_group(m)

    def on_dm(self, msg):
        f = self.dm_key(msg["from"], wait=True)
        raw = f and decrypt(f, msg["data"], TTL)
        if raw is None:                                    # F7
            self.warn(f"WARNING: DM from {msg['from']} failed integrity check - DISCARDED", "dm", msg["from"])
        else:
            self.out(f"[DM {msg['from']}] {raw.decode()}")
            self.emit("dm_msg", peer=msg["from"], sender=msg["from"], text=raw.decode(), mine=False)

    def on_group(self, msg):
        ver, token = msg["data"]["ver"], msg["data"]["token"]
        with self.slock:
            f = self.group_keys.get(ver)
            if f is None:
                self.pending.append(msg)                   # key not here yet; retry later
                return
        raw = decrypt(f, token, TTL)
        if raw is None:                                    # F7
            self.warn(f"WARNING: group message from {msg['from']} failed integrity check - DISCARDED", "group")
        else:
            self.out(f"[GROUP {msg['from']}] {raw.decode()}")
            self.emit("group_msg", sender=msg["from"], text=raw.decode(), mine=False)

    def on_file_chunk(self, msg):
        f = self.dm_key(msg["from"], wait=True)
        raw = f and decrypt(f, msg["data"], TTL)
        if raw is None:
            self.warn(f"WARNING: file chunk from {msg['from']} failed integrity check - DISCARDED", "dm", msg["from"])
            return
        c = json.loads(raw)
        ent = self.files.setdefault(c["id"], {"name": os.path.basename(c["name"]),
                                              "total": c["total"], "parts": {}})
        ent["parts"][c["idx"]] = base64.b64decode(c["b64"])
        if len(ent["parts"]) == ent["total"]:
            os.makedirs("received", exist_ok=True)
            path = os.path.join("received", f"{msg['from']}_{ent['name']}")
            with open(path, "wb") as fh:
                for i in range(ent["total"]):
                    fh.write(ent["parts"][i])
            del self.files[c["id"]]
            self.out(f"[FILE] received '{ent['name']}' from {msg['from']} -> saved to {path}")
            self.emit("file", peer=msg["from"], text=f"\U0001F4CE {ent['name']}  (received, click to open folder)",
                      mine=False, path=path, sender=msg["from"])

    # ---------- send side / commands ----------
    def send_group(self, text):
        with self.slock:
            f = self.group_keys.get(self.cur_ver)
            ver = self.cur_ver
        if f is None:
            self.warn("No group key yet, try again in a second", "group")
            return
        self._send("group", "*", {"ver": ver, "token": encrypt(f, text.encode())})
        self.out(f"[GROUP me] {text}")
        self.emit("group_msg", sender=self.name, text=text, mine=True)

    def send_dm(self, user, text):
        f = self.dm_key(user)
        if not f:
            self.warn(f"User '{user}' is not online", "dm", user)
            return
        self._send("dm", user, encrypt(f, text.encode()))
        self.out(f"[DM me -> {user}] {text}")
        self.emit("dm_msg", peer=user, sender=self.name, text=text, mine=True)

    def send_file(self, user, path):
        f = self.dm_key(user)
        if not f:
            self.warn(f"User '{user}' is not online", "dm", user)
            return
        if not os.path.isfile(path):
            self.warn(f"File not found: {path}", "dm", user)
            return
        data = open(path, "rb").read()
        total = max(1, -(-len(data) // CHUNK))
        tid = uuid.uuid4().hex
        for i in range(total):
            chunk = {"id": tid, "name": os.path.basename(path), "idx": i, "total": total,
                     "b64": base64.b64encode(data[i * CHUNK:(i + 1) * CHUNK]).decode()}
            self._send("file_chunk", user, encrypt(f, json.dumps(chunk).encode()))
        self.out(f"[FILE] sent '{os.path.basename(path)}' to {user} in {total} encrypted chunk(s)")
        self.emit("file", peer=user, text=f"\U0001F4CE {os.path.basename(path)}  (sent in {total} encrypted chunk(s))",
                  mine=True, path=None, sender=self.name)

    def handle_input(self, line):
        line = line.strip()
        if not line:
            return True
        if not line.startswith("/"):
            self.send_group(line)
            return True
        parts = line.split(" ", 2)
        cmd = parts[0]
        if cmd == "/quit":
            return False
        elif cmd == "/users":
            with self.slock:
                self.out("Online: " + ", ".join(u["username"] for u in self.users))
        elif cmd == "/dm" and len(parts) == 3:
            self.send_dm(parts[1], parts[2])
        elif cmd == "/send" and len(parts) == 3:
            self.send_file(parts[1], parts[2])
        elif cmd == "/fingerprint":
            if len(parts) == 1:
                self.out(f"Your fingerprint: {fingerprint(self.pub)}")
                with self.slock:
                    for u in self.users:
                        if u["username"] != self.name:
                            self.out(f"  {u['username']}: {fingerprint(u['pubkey'])}")
            else:
                pk = self.pubkey_of(parts[1])
                self.out(f"{parts[1]}: {fingerprint(pk)}" if pk else "[!] unknown user")
        else:
            self.out("Commands: /dm <user> <msg> | /users | /fingerprint [user] | /send <user> <file> | /quit")
        return True

    def close(self):
        self.running = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)   # unblocks the receive thread and tells the server
            self.sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python client.py <username> [host] [port]")
    c = Client(sys.argv[1],
               sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1",
               int(sys.argv[3]) if len(sys.argv) > 3 else 5000)
    print(f"Connected as {c.name}. Your fingerprint: {fingerprint(c.pub)}")
    print("Type text for group chat, or /dm /users /fingerprint /send /quit")
    try:
        while c.handle_input(input()):
            pass
    except (EOFError, KeyboardInterrupt):
        pass
    c.close()
