# Secure-Link: Secure Chat Application with End-to-End Encryption

A multi-user chat application built on TCP sockets in which **every message is end-to-end encrypted**. The server is only a relay: it registers users, shares public keys and forwards messages, but it never holds a private or shared key, so it can never read a message.

> **Course:** CS3001 Computer Networks, Fall 2026
> **University:** National University of Computer and Emerging Sciences (FAST-NUCES), Karachi
> **Project No. 2:** Secure Chat Application with End-to-End Encryption

| Member | ID |
|---|---|
| Zaid Bin Tariq | 24K-0789 |
| Muhammad Subhan | 24K-0784 |

---

## Table of contents

1. [Features](#features)
2. [How it works](#how-it-works)
3. [Project structure](#project-structure)
4. [Requirements and installation](#requirements-and-installation)
5. [Running the project](#running-the-project)
6. [Client commands](#client-commands)
7. [Running the eavesdropper (hacker) demos](#running-the-eavesdropper-hacker-demos)
8. [Running on two laptops](#running-on-two-laptops)
9. [Automated tests](#automated-tests)
10. [Wireshark verification](#wireshark-verification)
11. [Wire protocol](#wire-protocol)
12. [Security model and limitations](#security-model-and-limitations)
13. [Troubleshooting](#troubleshooting)
14. [References](#references)

---

## Features

| ID | Feature | Where |
|---|---|---|
| F1 | Multi-client threaded server (one thread per client, user table, relay only) | `server.py` |
| F2 | Client application with commands (`/dm`, `/users`, `/fingerprint`, `/send`, `/quit`) | `client.py` |
| F3 | Key generation and public key exchange (X25519, private key stays in memory) | `crypto_utils.py`, `client.py` |
| F4 | One-to-one end-to-end encrypted messaging | `crypto_utils.py`, `client.py` |
| F5 | Encrypted group chat | `client.py` |
| F6 | Eavesdropper ("hacker") module: passive sniffer and active tampering proxy, plus a GUI sniffer | `hacker.py`, `hacker_gui.py` |
| F7 | Message integrity and tamper detection, with replay rejection | `crypto_utils.py`, `client.py` |
| F8 | Key fingerprint verification | `crypto_utils.py`, `client.py`, `gui.py` |
| F9 | Encrypted file sharing (chunked) | `client.py` |
| F10 | Group key rotation on every join or leave | `client.py` |

A desktop GUI (`gui.py`) is also included. It uses the same `Client` class, so all security logic lives in one place.

---

## How it works

```
        alice            bob             carol
          \               |               /
           \              |              /
            +-------- Relay server ------+  <---- Sniffer (listen-only copy)
                     (never decrypts)
                          ^
                          |
                 Tampering proxy (optional, sits in front of the server)
```

The topology is a star: every client connects to the server, never to another client directly.

### Joining

1. The client generates an **X25519 key pair**. The private key stays in memory only.
2. It sends `register` with its public key. The server replies `register_ok`.
3. The server broadcasts `user_list` (every username and public key) to all clients.

### One-to-one messages (F4)

1. Alice combines **her private key** with **Bob's public key** (X25519) to get a shared secret.
2. The secret is passed through **HKDF-SHA256** to produce a 32-byte key, which becomes a **Fernet** key.
3. Bob does the same with his private key and Alice's public key and gets the **same** key. The key is never sent over the network.
4. Alice encrypts with Fernet, the server forwards the token, and Bob verifies and decrypts it.

### Group chat (F5) and key rotation (F10)

- All members share one **group Fernet key**, which is versioned (v1, v2, v3, ...). Each group message carries its version so messages in flight during a rotation still decrypt.
- Whenever a member **joins or leaves**, the **oldest online member** generates a fresh group key and sends it to each current member, encrypted with that member's one-to-one key.
- A user who left never receives the new key, so they cannot read new messages. A new joiner never receives old keys, so they cannot read old messages.

### Integrity and replay protection (F7)

Fernet = AES-128-CBC encryption + HMAC-SHA256 integrity tag, with a random IV and a timestamp per token. The receiver checks the tag first and decrypts only if it is valid. Tokens older than **300 seconds** (`TTL` in `client.py`) are rejected. Altered, expired or wrongly keyed messages are discarded with a warning and the client keeps running.

### Fingerprints (F8)

A fingerprint is the SHA-256 of a public key, shortened to 8 groups of 4 hex characters. Two users compare fingerprints over another channel (for example a phone call). If a malicious server had swapped a public key, the values would not match.

### File transfer (F9)

`/send <user> <file>` reads the file as raw bytes, splits it into **32 KB chunks**, and wraps each chunk with the transfer ID, file name, chunk index and total count. The whole wrapper is encrypted with the one-to-one key, so the server only sees Fernet tokens. The receiver reassembles the chunks in order and saves the file to `received/<sender>_<filename>`. Only the base filename is used, which blocks path traversal.

---

## Project structure

```
Secure-Link/
├── server.py          F1  Threaded relay server
├── client.py          F2-F5, F7-F10  Client logic (CLI entry point and Client class used by the GUI)
├── protocol.py        Message framing: 4-byte length header + JSON body
├── crypto_utils.py    Key generation, DM key derivation, fingerprints, encrypt/decrypt helpers
├── hacker.py          F6  Passive sniffer and tampering proxy (terminal)
├── hacker_gui.py      F6  Sniffer with a window
├── gui.py             Desktop chat client (Tkinter)
├── test_full.py       Automated test of F1-F10
├── requirements.txt   Python dependencies
└── README.md
```

Folders created at runtime: `received/` (files received by clients).

---

## Requirements and installation

- **Python 3.8 or newer**
- **`cryptography` >= 42.0** (installed through pip)
- **Tkinter**, only for `gui.py` and `hacker_gui.py`. It is part of the Python standard library and is **not** installed with pip.

### 1. Install the dependency

```bash
pip install -r requirements.txt
```

On Linux and macOS use `pip3` and `python3` if `pip` and `python` point to Python 2 or are missing.

### 2. Make sure Tkinter is available (GUI only)

| Platform | What to do |
|---|---|
| Windows | Included with the python.org installer. If you customized the install, tick "tcl/tk and IDLE". |
| Ubuntu / Debian | `sudo apt install python3-tk` |
| Fedora | `sudo dnf install python3-tkinter` |
| macOS | Included with python.org installers. With Homebrew: `brew install python-tk` |

Check it with:

```bash
python -c "import tkinter; print('Tkinter OK')"
```

The terminal client (`client.py`, `hacker.py`) and `test_full.py` work without Tkinter. On Linux the GUI needs a graphical desktop session.

---

## Running the project

Always start the **server first**. Open one terminal per program, all inside the project folder.

### Terminal client

```bash
python server.py                 # terminal 1
python client.py alice           # terminal 2
python client.py bob             # terminal 3
```

Start the clients one at a time and wait a second between them. The first client to join is the oldest member and creates the group key; every join triggers a key rotation, so you will see `group key rotated` and `received group key` lines.

Usage: `python client.py <username> [host] [port]`

### GUI client

```bash
python server.py
python gui.py                    # run once per user
```

Enter a username, the server address (default `127.0.0.1`) and the port (default `5000`), then click **Connect securely**. The GUI shows:

- a **conversation list** with the group chat and private chats (online and offline contacts)
- the current **group key version** in the header
- a **security panel** with your fingerprint, your contact's fingerprint, the cryptography in use, and a live security log
- a **paperclip button** to send an encrypted file in a private chat

### Choosing a different port

```bash
python server.py 5002
python client.py alice 127.0.0.1 5002
```

---

## Client commands

| Command | Description |
|---|---|
| `<text>` | Group message, encrypted with the group key |
| `/dm <user> <msg>` | End-to-end encrypted private message |
| `/users` | List online users |
| `/fingerprint` | Show your fingerprint and everyone else's |
| `/fingerprint <user>` | Show one user's fingerprint |
| `/send <user> <file>` | Send an encrypted file to one user (any file type, one file at a time) |
| `/quit` | Disconnect and exit |

Notes:

- There is **one group**. Everyone connected to the server is in it automatically. Anything that does not start with `/` goes to the group.
- A new joiner cannot read messages sent before they joined (by design, F10).
- Right after joining there may be a moment before the group key arrives. If you see `no group key yet, try again in a second`, wait briefly and retry.
- Usernames cannot contain spaces, and `*` and `server` are reserved.
- Received files are saved in `received/` as `<sender>_<filename>`.

---

## Running the eavesdropper (hacker) demos

### Passive sniffer (terminal)

```bash
python hacker.py sniff [host] [port]
```

Connects as a silent listener. The server copies every relayed packet to it. It sees who talks to whom, the message type and the ciphertext, but **never the content**.

### Passive sniffer (GUI)

```bash
python hacker_gui.py
```

Lists every intercepted packet in a table. Select a packet to see the full ciphertext, then click **Try to decrypt**. It always fails (`InvalidToken`), because the attacker has no key. This connects to `127.0.0.1:5000`, so run it on the machine that hosts the server, or edit the host and port in `hacker_gui.py`.

### Tampering proxy (active man-in-the-middle)

```bash
python hacker.py proxy [listen_port] [server_host] [server_port]
```

Defaults: listens on `5001`, forwards to `127.0.0.1:5000`. Clients that connect to the proxy instead of the server have their outgoing encrypted messages **corrupted**:

```bash
python hacker.py proxy
python client.py dave 127.0.0.1 5001
```

Other users then see `WARNING: ... failed integrity check - DISCARDED`, which demonstrates F7. Only messages sent by a client connected through the proxy are corrupted.

---

## Running on two laptops

Laptop A runs the server, Laptop B connects to it. Both need the project folder and `pip install -r requirements.txt`. Windows and Linux can be mixed freely.

1. Put both laptops on the **same network**. If the network blocks device-to-device traffic, use a phone hotspot.
2. On Laptop A, find its IP address: `ipconfig` on Windows (IPv4 Address) or `ip a` on Linux.
3. On Laptop A, allow the server through the firewall:
   - Windows: click **Allow access** when prompted, or add an inbound rule for TCP port 5000.
   - Ubuntu with ufw: `sudo ufw allow 5000/tcp`
4. Start the programs:

```bash
# Laptop A
python server.py
python client.py alice

# Laptop B (replace with Laptop A's real IP)
python client.py bob 192.168.1.23 5000
```

Start alice first so she is the oldest member. To check connectivity from Laptop B first, run `ping 192.168.1.23`.

---

## Automated tests

```bash
python test_full.py
```

The script starts its own server (port `5100`) and tampering proxy (port `5101`), then runs alice, bob, carol and dave through every feature. Each check prints `PASS` or `FAIL`, and the run ends with `ALL TESTS PASSED`. It takes about 20 seconds.

| Test | Feature |
|---|---|
| Key version is v3 for all three clients after joining | F10 rotation on join |
| Group message reaches bob and carol | F5 |
| DM reaches bob, carol receives nothing | F4 |
| 100,000-byte file arrives identical (4 chunks) | F9 |
| Fingerprint command works | F8 |
| Tampered DM and tampered group message are rejected | F7 |
| After carol leaves, the key rotates and she never gets the new key | F10 rotation on leave |
| Remaining members still chat after rotation | F5 / F10 |

The test creates `t.txt` and a `received/` folder in the working directory.

---

## Wireshark verification

Wireshark gives extra proof on the wire that messages are unreadable.

1. Start Wireshark and capture on the right interface: **loopback** if everything runs on one machine, your **Wi-Fi adapter** if the clients are on different laptops.
2. Apply the display filter `tcp.port == 5000`.
3. Send some chat messages and a file.
4. Right-click a packet and choose **Follow, TCP Stream**. You will see JSON frames (type, from, to) with long Fernet tokens starting with `gAAAA...` and no readable message text.

---

## Wire protocol

TCP is a byte stream with no message boundaries, so every message is framed:

```
[ 4-byte big-endian length ][ UTF-8 JSON body ]
```

The JSON body always has four fields: `{"type", "from", "to", "data"}`. `to` is `"*"` for a broadcast or a username for a unicast. Frames larger than 4 MB are refused.

| Type | Direction | `data` |
|---|---|---|
| `register` | client → server | `{"pubkey": base64, "role": "user" or "sniffer"}` |
| `register_ok` | server → client | `{}` |
| `error` | server → client | reason string |
| `user_list` | server → clients | `[{"username", "pubkey"}, ...]` in join order |
| `dm` | client → client | Fernet token |
| `group` | client → all | `{"ver": int, "token": Fernet token}` |
| `group_key` | client → client | Fernet token containing `{"ver", "key"}`, encrypted with the one-to-one key |
| `file_chunk` | client → client | Fernet token containing the chunk wrapper |

The server overwrites `from` with the real sender's username, so a client cannot impersonate another.

### Cryptography summary

| Purpose | Algorithm |
|---|---|
| Key exchange | X25519 |
| Key derivation | HKDF-SHA256 (`info = "securechat-dm-v1"`) |
| Message encryption | Fernet (AES-128-CBC) |
| Integrity and replay check | HMAC-SHA256 and token timestamp (TTL 300 s) |
| Fingerprint | SHA-256 of the public key, first 128 bits |

---

## Security model and limitations

**What is protected**

- The server and any sniffer see only public keys, metadata (who talks to whom, message type, size) and ciphertext.
- Altered, expired or wrongly keyed messages are rejected.
- Removed users cannot read new group messages, and new joiners cannot read old ones.

**Known limitations**

- **Trusting the server for public keys.** A malicious server could swap public keys. Fingerprint comparison (F8) over a separate channel is the defence, and it relies on users actually doing it.
- **Replay window.** Replay protection is a 5-minute time limit, so a replay inside that window would be accepted.
- **Group key sender is not checked.** Any member whose private message decrypts can send a `group_key`. A hardened version would accept keys only from the oldest member.
- **No forward secrecy.** A user who leaves keeps the old keys and can still decrypt traffic they captured earlier. They lose access only to new messages.
- **Single rotator.** If the oldest member disconnects while distributing a key, some members may miss it until the next join or leave.
- **Metadata is visible.** Usernames, the message type and the key version of group messages are not encrypted.
- **Files are held in memory** on both sides and are sent to one user at a time. Very large files will be slow. A file with a missing or corrupted chunk is never saved.
- **No persistence.** There are no accounts and no message history. A user must be online to receive anything.
- **Educational project.** It has not been audited and is not intended for real-world secrets.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: cryptography` | Run `pip install -r requirements.txt` (use `pip3` on Linux/macOS) |
| `ModuleNotFoundError: tkinter` | Install Tkinter, see [Requirements](#requirements-and-installation) |
| `Address already in use` | An old server is still running. Close it, or use another port: `python server.py 5002` |
| `ConnectionRefusedError` or timeout | The server is not running, the IP is wrong, or the firewall blocks port 5000 |
| `Registration failed: username invalid or already taken` | Pick a different name without spaces. `*` and `server` are reserved |
| `no group key yet, try again in a second` | Wait a moment after joining; the group key is still arriving |
| `user '...' is not online` | That user is not connected, or you have not received the latest user list yet |
| Second laptop cannot connect | Check the server's IP with `ipconfig` or `ip a`, test with `ping`, check the firewall, or try a phone hotspot |
| GUI window does not open on Linux | A graphical session is required; check that `python3-tk` is installed |

---

## References

1. CS3001 Computer Networks, Project List, Fall 2026, Project No. 2: Secure Chat Application with End-to-End Encryption.
2. Python Software Foundation, "socket - Low-level networking interface", https://docs.python.org/3/library/socket.html
3. Python Software Foundation, "threading - Thread-based parallelism", https://docs.python.org/3/library/threading.html
4. Python Cryptographic Authority, "cryptography" documentation, https://cryptography.io/
5. A. Langley, M. Hamburg, S. Turner, "Elliptic Curves for Security", RFC 7748, https://www.rfc-editor.org/rfc/rfc7748
6. Fernet specification, https://github.com/fernet/spec/blob/master/Spec.md
7. Wireshark User's Guide, https://www.wireshark.org/docs/wsug_html_chunked/