"""
server.py -- F1: multi-client threaded relay server (Member 1).
The server NEVER decrypts anything. It only:
  1. registers usernames + public keys
  2. broadcasts the user list on join/leave
  3. relays messages (and copies them to any "sniffer" client for the hacker demo)
"""
import socket #tcp 
import sys
import threading

from protocol import recv_msg, send_msg

#0.0.0.0 : lstens to all network interfaces, 5000: default port
HOST, PORT = "0.0.0.0", 5000

lock = threading.Lock() #protects the two structures below
clients = {} #username -> {"sock", "pubkey", "wlock"}  (insertion = join order)
sniffers = [] #list of {"sock", "wlock"}  (hacker clients)


# safe_send sends one message to one client in a thread-safe way and it doesn't crash if that client has already disconnected.
def safe_send(entry, msg):
    try:
        with entry["wlock"]:#one thread can send to a socket at a time, without lock it causes sync issue(OS concept)
            send_msg(entry["sock"], msg)
    except OSError:
        pass #ignore disconnected socket/client


def broadcast_user_list(): #list of users+public key while holdng the lock
    with lock:
        users = [{"username": u, "pubkey": c["pubkey"]} for u, c in clients.items()]
        targets = list(clients.values())
    msg = {"type": "user_list", "from": "server", "to": "*", "data": users}
    for t in targets:
        safe_send(t, msg) #send user list to all clients so they can know each other public keys

def copy_to_sniffers(msg):
    with lock:
        snaps = list(sniffers)
    for s in snaps:
        safe_send(s, msg)


def handle_client(sock, addr):
    entry = {"sock": sock, "wlock": threading.Lock()}
    username = None
    is_sniffer = False
    try:
        # ---- registration ----
        msg = recv_msg(sock)
        if not msg or msg.get("type") != "register": #first msg msut be register
            return
        name = str(msg.get("from", "")).strip()
        data = msg.get("data") or {}
        if data.get("role") == "sniffer":
            #sniffer kept away from clients list
            is_sniffer = True
            with lock:
                sniffers.append(entry)
            safe_send(entry, {"type": "register_ok", "from": "server", "to": name, "data": {}})
            print(f"[+] sniffer connected from {addr}")
        else:
            with lock:
                #rejected names: empty, broadcast address(*), server, contains space, already taken
                bad = (not name or name in ("*", "server") or " " in name or name in clients)
                if not bad:
                    entry["pubkey"] = data.get("pubkey", "")
                    clients[name] = entry
            if bad:
                safe_send(entry, {"type": "error", "from": "server", "to": name,
                                  "data": "username invalid or already taken"})
                return
            username = name
            safe_send(entry, {"type": "register_ok", "from": "server", "to": name, "data": {}}) #new user added
            print(f"[+] {username} joined from {addr}")
            broadcast_user_list()#new user shared with everyone

        # ---- relay loop ----
        while True:
            msg = recv_msg(sock)
            if msg is None:
                break
            if is_sniffer:
                continue #sniffers are listen-only
            msg["from"] = username  #server stamps sender: client cannot pretend to be anyone else
            to = msg.get("to")
            print(f"[relay] {msg.get('type')}: {username} -> {to} | {str(msg.get('data'))[:70]}...")
            copy_to_sniffers(msg)
            if to == "*": #broadcast msg, send to all clients except sender
                with lock:
                    targets = [c for u, c in clients.items() if u != username]
                for t in targets:
                    safe_send(t, msg)
            else: #DM 
                with lock:
                    target = clients.get(to)
                if target:
                    safe_send(target, msg)
                else:
                    safe_send(entry, {"type": "error", "from": "server", "to": username,
                                      "data": f"user '{to}' is not online"})
    except (OSError, ValueError):
        pass
    finally:
        with lock:
            if username and clients.get(username) is entry:
                del clients[username]
            if entry in sniffers:
                sniffers.remove(entry)
        sock.close()
        if username:
            print(f"[-] {username} left")
            broadcast_user_list() #updated user list and also triggers key rotation (f10)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen()
    print(f"Server listening on {HOST}:{port}")
    while True:
        sock, addr = srv.accept()
        threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()


if __name__ == "__main__":
    main()
