"""
hacker.py -- F6 eavesdropper.
  python hacker.py sniff [host] [port]     passive: gets a copy of every relayed packet
  python hacker.py proxy [listen_port] [server_host] [server_port]
        active man-in-the-middle: clients connect to the proxy (default 5001) instead of the
        server (5000); it forwards everything but CORRUPTS each encrypted message, so you can
        show that F7 detects tampering.
"""
import socket
import sys
import threading

from protocol import recv_msg, send_msg


def show(m, tag=""):
    d = m.get("data")
    tok = d.get("token") if isinstance(d, dict) and "token" in d else d
    print(f"{tag}[{m.get('type')}] {m.get('from')} -> {m.get('to')} | "
          f"{str(tok)[:64]}{'...' if len(str(tok)) > 64 else ''}")


def sniff(host, port):
    s = socket.create_connection((host, port))
    send_msg(s, {"type": "register", "from": "hacker", "to": "server",
                 "data": {"role": "sniffer"}})
    recv_msg(s)
    print("Hacker is listening... (everything below is what an eavesdropper sees)\n")
    while True:
        m = recv_msg(s)
        if m is None:
            break
        if m["type"] == "user_list":
            print("[user_list] public keys visible: " + ", ".join(u["username"] for u in m["data"]))
        else:
            show(m, "INTERCEPTED ")
            print("   -> cannot decrypt: no key. Content UNREADABLE.\n")


def corrupt(tok):
    i = len(tok) // 2
    return tok[:i] + ("A" if tok[i] != "A" else "B") + tok[i + 1:]


def pipe(src, dst, tamper):
    try:
        while True:
            m = recv_msg(src)
            if m is None:
                break
            if tamper and m["type"] in ("dm", "group", "file_chunk", "group_key"):
                show(m, "ORIGINAL  ")
                if isinstance(m["data"], dict):
                    m["data"]["token"] = corrupt(m["data"]["token"])
                else:
                    m["data"] = corrupt(m["data"])
                show(m, "TAMPERED  ")
            send_msg(dst, m)
    except (OSError, ValueError):
        pass
    finally:
        for x in (src, dst):
            try:
                x.close()
            except OSError:
                pass


def proxy(lport, host, port):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("0.0.0.0", lport))
    ls.listen()
    print(f"Tampering proxy on :{lport} -> {host}:{port}")
    while True:
        c, _ = ls.accept()
        s = socket.create_connection((host, port))
        threading.Thread(target=pipe, args=(c, s, True), daemon=True).start()   # client->server: tamper
        threading.Thread(target=pipe, args=(s, c, False), daemon=True).start()  # server->client: pass


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "sniff"
    a = sys.argv[2:]
    if mode == "sniff":
        sniff(a[0] if a else "127.0.0.1", int(a[1]) if len(a) > 1 else 5000)
    else:
        proxy(int(a[0]) if a else 5001, a[1] if len(a) > 1 else "127.0.0.1",
              int(a[2]) if len(a) > 2 else 5000)
