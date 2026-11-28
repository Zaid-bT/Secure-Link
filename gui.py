"""
gui.py -- SecureChat desktop client (Tkinter).  Run:  python gui.py
(the server must already be running:  python server.py)

All security logic lives in client.py / crypto_utils.py. This file only draws the window
and reacts to events that Client emits (messages, key rotations, warnings, ...).
"""
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, ttk

from client import Client
from crypto_utils import fingerprint

# ---------- theme ----------
BG, SIDE, PANEL, FIELD = "#0f1420", "#0a0e17", "#171d2b", "#1f2638"
TEXT, MUTED = "#e6e9f0", "#8b93a7"
ACCENT, ACCENT_H = "#6c63ff", "#8179ff"
MINE, THEIRS = "#4a44c6", "#2a3248"
OK, BAD, WARN = "#34d399", "#f87171", "#fbbf24"
FONT = ("Segoe UI", 10)
BOLD = ("Segoe UI", 10, "bold")
SMALL = ("Segoe UI", 8)
MONO = ("Consolas", 10)


def now():
    return time.strftime("%H:%M")


def open_folder(path):
    folder = os.path.dirname(os.path.abspath(path))
    try:
        if hasattr(os, "startfile"):
            os.startfile(folder)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", folder])
        else:
            subprocess.Popen(["xdg-open", folder])
    except OSError:
        pass


def mkbtn(parent, text, cmd, primary=True, **kw):
    bg = ACCENT if primary else FIELD
    hover = ACCENT_H if primary else "#2b3550"
    b = tk.Button(parent, text=text, command=cmd, bg=bg, fg="white", activebackground=hover,
                  activeforeground="white", relief="flat", bd=0, padx=16, pady=8,
                  cursor="hand2", font=BOLD, disabledforeground=MUTED, **kw)
    b.bind("<Enter>", lambda e: b["state"] == "normal" and b.config(bg=hover))
    b.bind("<Leave>", lambda e: b.config(bg=bg))
    return b


def mkentry(parent, **kw):
    return tk.Entry(parent, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat",
                    font=("Segoe UI", 11), highlightthickness=1, highlightbackground=FIELD,
                    highlightcolor=ACCENT, disabledbackground=FIELD, **kw)


class SecureChatApp:
    def __init__(self, root):
        self.root = root
        root.title("SecureChat - End-to-End Encrypted")
        root.geometry("1180x720")
        root.minsize(980, 600)
        root.configure(bg=BG)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Vertical.TScrollbar", background=FIELD, troughcolor=BG,
                        bordercolor=BG, arrowcolor=MUTED, lightcolor=FIELD, darkcolor=FIELD)

        self.q = queue.Queue()          # events from network threads -> UI thread
        self.early = []                 # events that arrive before the main screen exists
        self.client = None
        self.convs = {"group": []}      # conversation key -> list of items
        self.unread = {}
        self.users = []
        self.current = "group"
        self.keys = ["group"]
        self.key_ver = 0
        self.link_counter = 0
        self._refreshing = False

        self.build_login()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(100, self.poll)

    # ======================= LOGIN SCREEN =======================
    def build_login(self):
        f = tk.Frame(self.root, bg=BG)
        f.pack(fill="both", expand=True)
        self.login_frame = f
        card = tk.Frame(f, bg=PANEL, padx=44, pady=34)
        card.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(card, text="\U0001F512", font=("Segoe UI Emoji", 34), bg=PANEL, fg=ACCENT).pack()
        tk.Label(card, text="SecureChat", font=("Segoe UI", 22, "bold"), bg=PANEL, fg=TEXT).pack()
        tk.Label(card, text="End-to-end encrypted messaging\nThe server can never read your messages",
                 font=FONT, bg=PANEL, fg=MUTED, justify="center").pack(pady=(2, 20))

        def field(label, default):
            tk.Label(card, text=label, font=SMALL, bg=PANEL, fg=MUTED, anchor="w").pack(fill="x", pady=(8, 2))
            e = mkentry(card, width=32)
            e.insert(0, default)
            e.pack(fill="x", ipady=7)
            return e

        self.e_name = field("USERNAME", "")
        self.e_host = field("SERVER ADDRESS", "127.0.0.1")
        self.e_port = field("PORT", "5000")
        self.btn_connect = mkbtn(card, "Connect securely", self.connect)
        self.btn_connect.pack(fill="x", pady=(20, 6))
        self.status = tk.Label(card, text="", bg=PANEL, fg=BAD, font=FONT, wraplength=320)
        self.status.pack()
        self.e_name.focus_set()
        self.root.bind("<Return>", lambda e: self.connect())

    def connect(self):
        name = self.e_name.get().strip()
        host = self.e_host.get().strip() or "127.0.0.1"
        try:
            port = int(self.e_port.get().strip())
        except ValueError:
            self.status.config(text="Port must be a number")
            return
        if not name or " " in name or name in ("*", "server"):
            self.status.config(text="Enter a username without spaces")
            return
        self.btn_connect.config(state="disabled", text="Generating keys & connecting...")
        self.status.config(text="")

        def work():
            try:
                c = Client(name, host, port, quiet=True,
                           on_event=lambda kind, **kw: self.q.put((kind, kw)))
                self.q.put(("login_ok", {"client": c}))
            except SystemExit as e:
                self.q.put(("login_error", {"text": str(e) or "Registration failed"}))
            except OSError:
                self.q.put(("login_error", {"text": f"Cannot reach a server at {host}:{port}.\nIs server.py running?"}))
        threading.Thread(target=work, daemon=True).start()

    # ======================= MAIN SCREEN =======================
    def build_main(self):
        self.login_frame.destroy()
        self.root.unbind("<Return>")
        m = tk.Frame(self.root, bg=BG)
        m.pack(fill="both", expand=True)
        m.columnconfigure(1, weight=1)
        m.rowconfigure(1, weight=1)

        # ---- header ----
        hdr = tk.Frame(m, bg=SIDE, height=54)
        hdr.grid(row=0, column=0, columnspan=3, sticky="ew")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="\U0001F512  SecureChat", font=("Segoe UI", 14, "bold"), bg=SIDE, fg=TEXT).pack(side="left", padx=18)
        self.lbl_conn = tk.Label(hdr, text=f"\u25CF {self.client.name}  connected", font=BOLD, bg=SIDE, fg=OK)
        self.lbl_conn.pack(side="right", padx=18)
        self.lbl_key = tk.Label(hdr, text="\U0001F511 Group key: waiting...", font=BOLD, bg=FIELD, fg=WARN, padx=10, pady=4)
        self.lbl_key.pack(side="right", padx=6)

        # ---- sidebar ----
        side = tk.Frame(m, bg=SIDE, width=250)
        side.grid(row=1, column=0, sticky="ns")
        side.pack_propagate(False)
        tk.Label(side, text="CONVERSATIONS", font=SMALL, bg=SIDE, fg=MUTED, anchor="w").pack(fill="x", padx=18, pady=(18, 8))
        self.lb = tk.Listbox(side, bg=SIDE, fg=TEXT, selectbackground=ACCENT, selectforeground="white",
                             font=("Segoe UI", 11), relief="flat", bd=0, highlightthickness=0,
                             activestyle="none", exportselection=False)
        self.lb.pack(fill="both", expand=True, padx=8)
        self.lb.bind("<<ListboxSelect>>", self.on_select)
        tk.Label(side, text=f"Signed in as  {self.client.name}", font=SMALL, bg=SIDE, fg=MUTED).pack(pady=12)

        # ---- centre ----
        center = tk.Frame(m, bg=BG)
        center.grid(row=1, column=1, sticky="nsew")
        center.columnconfigure(0, weight=1)
        center.rowconfigure(1, weight=1)
        top = tk.Frame(center, bg=PANEL)
        top.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.lbl_title = tk.Label(top, text="", font=("Segoe UI", 13, "bold"), bg=PANEL, fg=TEXT, anchor="w")
        self.lbl_title.pack(fill="x", padx=18, pady=(10, 0))
        self.lbl_sub = tk.Label(top, text="", font=SMALL, bg=PANEL, fg=OK, anchor="w")
        self.lbl_sub.pack(fill="x", padx=18, pady=(0, 10))

        self.chat = tk.Text(center, bg=BG, fg=TEXT, wrap="word", relief="flat", bd=0, padx=6, pady=8,
                            font=("Segoe UI", 11), state="disabled", highlightthickness=0, cursor="arrow")
        self.chat.grid(row=1, column=0, sticky="nsew")
        sb = ttk.Scrollbar(center, orient="vertical", command=self.chat.yview)
        sb.grid(row=1, column=1, sticky="ns")
        self.chat.config(yscrollcommand=sb.set)
        self.config_tags()

        bar = tk.Frame(center, bg=PANEL, padx=12, pady=12)
        bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.btn_attach = mkbtn(bar, "\U0001F4CE", self.attach, primary=False)
        self.btn_attach.pack(side="left", padx=(0, 8))
        self.entry = mkentry(bar)
        self.entry.pack(side="left", fill="x", expand=True, ipady=8)
        self.entry.bind("<Return>", lambda e: self.send())
        self.btn_send = mkbtn(bar, "Send  \u27A4", self.send)
        self.btn_send.pack(side="left", padx=(8, 0))

        # ---- security panel ----
        right = tk.Frame(m, bg=PANEL, width=290)
        right.grid(row=1, column=2, sticky="ns")
        right.pack_propagate(False)
        tk.Label(right, text="SECURITY", font=SMALL, bg=PANEL, fg=MUTED, anchor="w").pack(fill="x", padx=16, pady=(18, 6))
        tk.Label(right, text="Your key fingerprint", font=BOLD, bg=PANEL, fg=TEXT, anchor="w").pack(fill="x", padx=16)
        self.lbl_myfp = tk.Label(right, text=self.fp_text(self.client.pub), font=MONO, bg=FIELD, fg=OK,
                                 justify="left", padx=10, pady=8)
        self.lbl_myfp.pack(fill="x", padx=16, pady=(4, 12))
        self.lbl_peer_t = tk.Label(right, text="Contact's fingerprint", font=BOLD, bg=PANEL, fg=TEXT, anchor="w")
        self.lbl_peer_t.pack(fill="x", padx=16)
        self.lbl_peerfp = tk.Label(right, text="", font=MONO, bg=FIELD, fg=WARN, justify="left",
                                   padx=10, pady=8, wraplength=250)
        self.lbl_peerfp.pack(fill="x", padx=16, pady=(4, 6))
        tk.Label(right, text="Compare this with your contact over a phone call. If it differs from what "
                 "they see, someone is swapping keys (man-in-the-middle).", font=SMALL, bg=PANEL, fg=MUTED,
                 wraplength=255, justify="left", anchor="w").pack(fill="x", padx=16, pady=(0, 12))
        tk.Label(right, text="Cryptography in use", font=BOLD, bg=PANEL, fg=TEXT, anchor="w").pack(fill="x", padx=16)
        tk.Label(right, text="Key exchange: X25519\nKey derivation: HKDF-SHA256\nCipher: Fernet (AES-128-CBC)\n"
                 "Integrity: HMAC-SHA256", font=SMALL, bg=PANEL, fg=MUTED, justify="left", anchor="w").pack(fill="x", padx=16, pady=(4, 12))
        tk.Label(right, text="Security log", font=BOLD, bg=PANEL, fg=TEXT, anchor="w").pack(fill="x", padx=16)
        self.log = tk.Text(right, bg=FIELD, fg=MUTED, font=SMALL, wrap="word", relief="flat", bd=0, padx=8,
                           pady=6, state="disabled", height=10, highlightthickness=0)
        self.log.pack(fill="both", expand=True, padx=16, pady=(4, 16))
        self.log.tag_config("info", foreground=MUTED)
        self.log.tag_config("ok", foreground=OK)
        self.log.tag_config("bad", foreground=BAD)

        self.add_log("Key pair generated. Private key stays in memory only.", "ok")
        self.refresh_sidebar()
        self.show_conversation()

    def config_tags(self):
        t = self.chat
        big = ("Segoe UI", 11)
        t.tag_config("mine_hdr", justify="right", foreground=MUTED, font=SMALL, lmargin1=150, lmargin2=150, rmargin=18, spacing1=8)
        t.tag_config("mine", justify="right", background=MINE, foreground="white", font=big,
                     lmargin1=150, lmargin2=150, rmargin=18, spacing1=2, spacing3=2)
        t.tag_config("theirs_hdr", justify="left", foreground=OK, font=("Segoe UI", 8, "bold"), lmargin1=18, lmargin2=18, rmargin=150, spacing1=8)
        t.tag_config("theirs", justify="left", background=THEIRS, foreground=TEXT, font=big,
                     lmargin1=18, lmargin2=18, rmargin=150, spacing1=2, spacing3=2)
        t.tag_config("mine_pad", justify="right", lmargin1=150, lmargin2=150, rmargin=18, spacing1=2, spacing3=2)
        t.tag_config("sys", justify="center", foreground=MUTED, font=SMALL, spacing1=8, spacing3=4)
        t.tag_config("warn", justify="center", foreground=BAD, font=("Segoe UI", 9, "bold"), spacing1=8, spacing3=4)
        t.tag_config("gap", font=("Segoe UI", 3))

    @staticmethod
    def fp_text(pub):
        w = fingerprint(pub).split()
        return " ".join(w[:4]) + "\n" + " ".join(w[4:])

    # ======================= EVENT PUMP =======================
    def poll(self):
        try:
            while True:
                kind, kw = self.q.get_nowait()
                self.dispatch(kind, kw)
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def dispatch(self, kind, kw):
        if kind == "login_ok":
            self.client = kw["client"]
            self.build_main()
            early, self.early = self.early, []
            for k, w in early:
                self.dispatch(k, w)
            self.entry.focus_set()
            return
        if kind == "login_error":
            self.status.config(text=kw["text"])
            self.btn_connect.config(state="normal", text="Connect securely")
            return
        if self.client is None:
            self.early.append((kind, kw))
            return
        handler = getattr(self, "ev_" + kind, None)
        if handler:
            handler(**kw)

    # ---- events coming from Client ----
    def ev_users(self, users):
        self.users = users
        self.refresh_sidebar()
        self.refresh_title()

    def ev_system(self, text):
        self.add_item("group", {"kind": "sys", "text": text}, count_unread=False)
        self.add_log(text, "info")

    def ev_key(self, ver, text):
        self.key_ver = max(self.key_ver, ver)
        self.lbl_key.config(text=f"\U0001F511 Group key v{self.key_ver}", fg=OK)
        self.add_log(text, "ok")
        self.refresh_title()

    def ev_warning(self, text, scope="system", peer=None):
        self.add_log(text, "bad")
        conv = "group" if scope == "group" else (peer if scope == "dm" and peer else self.current)
        self.add_item(conv, {"kind": "warn", "text": text}, count_unread=False)

    def ev_group_msg(self, sender, text, mine):
        self.add_item("group", {"kind": "msg", "sender": sender, "text": text, "mine": mine, "ts": now()})

    def ev_dm_msg(self, peer, sender, text, mine):
        self.add_item(peer, {"kind": "msg", "sender": sender, "text": text, "mine": mine, "ts": now()})

    def ev_file(self, peer, text, mine, path, sender):
        self.add_item(peer, {"kind": "file", "sender": sender, "text": text, "mine": mine, "ts": now(), "path": path})
        self.add_log(("Sent" if mine else "Received") + " encrypted file " + ("to " if mine else "from ") + peer, "ok")

    def ev_disconnected(self):
        self.lbl_conn.config(text="\u25CF disconnected", fg=BAD)
        self.entry.config(state="disabled")
        self.btn_send.config(state="disabled")
        self.add_log("Disconnected from server", "bad")

    # ======================= CONVERSATIONS =======================
    def add_item(self, conv, item, count_unread=True):
        new = conv not in self.convs
        self.convs.setdefault(conv, []).append(item)
        if conv == self.current:
            self.render_item(item)
        elif count_unread and not item.get("mine"):
            self.unread[conv] = self.unread.get(conv, 0) + 1
        if new or conv != self.current:
            self.refresh_sidebar()

    def refresh_sidebar(self):
        me = self.client.name
        online = [u["username"] for u in self.users if u["username"] != me]
        others = [k for k in self.convs if k != "group" and k not in online]
        self.keys = ["group"] + online + others
        self._refreshing = True
        self.lb.delete(0, "end")
        for i, k in enumerate(self.keys):
            if k == "group":
                label = "   #   Group chat"
            else:
                dot = "\u25CF" if k in online else "\u25CB"
                label = f"   {dot}   {k}"
            n = self.unread.get(k, 0)
            if n:
                label += f"    \u25CF {n}"
            self.lb.insert("end", label)
            if k == "group" or k in online:
                self.lb.itemconfig(i, fg=WARN if n else TEXT)
            else:
                self.lb.itemconfig(i, fg=MUTED)
        if self.current in self.keys:
            idx = self.keys.index(self.current)
            self.lb.selection_set(idx)
        self._refreshing = False

    def on_select(self, _event):
        if self._refreshing:
            return
        sel = self.lb.curselection()
        if not sel:
            return
        key = self.keys[sel[0]]
        if key == self.current:
            return
        self.current = key
        self.unread.pop(key, None)
        self.refresh_sidebar()
        self.show_conversation()
        self.entry.focus_set()

    def show_conversation(self):
        self.chat.config(state="normal")
        self.chat.delete("1.0", "end")
        self.chat.config(state="disabled")
        for it in self.convs.get(self.current, []):
            self.render_item(it)
        self.refresh_title()

    def refresh_title(self):
        if self.current == "group":
            n = len(self.users)
            self.lbl_title.config(text="#  Group chat")
            self.lbl_sub.config(text=f"\U0001F512 {n} member(s) online  \u00B7  shared group key v{self.key_ver}, "
                                     f"replaced whenever someone joins or leaves", fg=OK)
            self.btn_attach.config(state="disabled")
            self.lbl_peer_t.config(text="Contact's fingerprint")
            self.lbl_peerfp.config(text="Open a private chat to see\na contact's fingerprint.", fg=MUTED)
        else:
            pk = self.client.pubkey_of(self.current)
            online = pk is not None
            self.lbl_title.config(text=self.current + ("" if online else "   (offline)"))
            self.lbl_sub.config(text="\U0001F512 Private chat  \u00B7  end-to-end encrypted with a key only you two can derive",
                                fg=OK if online else MUTED)
            self.btn_attach.config(state="normal" if online else "disabled")
            self.lbl_peer_t.config(text=f"{self.current}'s fingerprint")
            if pk:
                self.lbl_peerfp.config(text=self.fp_text(pk), fg=WARN)
            else:
                self.lbl_peerfp.config(text="(user is offline)", fg=MUTED)

    def render_item(self, it):
        t = self.chat
        t.config(state="normal")
        k = it["kind"]
        if k == "sys":
            t.insert("end", f"{it['text']}\n", "sys")
        elif k == "warn":
            t.insert("end", f"\u26A0  {it['text']}\n", "warn")
        else:
            side = "mine" if it["mine"] else "theirs"
            who = "You" if it["mine"] else it["sender"]
            t.insert("end", f"{who}  \u00B7  {it['ts']}\n", side + "_hdr")
            tags = (side,)
            if k == "file" and it.get("path"):
                tag = f"lnk{self.link_counter}"
                self.link_counter += 1
                t.tag_config(tag, underline=True)
                t.tag_bind(tag, "<Button-1>", lambda e, p=it["path"]: open_folder(p))
                t.tag_bind(tag, "<Enter>", lambda e: t.config(cursor="hand2"))
                t.tag_bind(tag, "<Leave>", lambda e: t.config(cursor="arrow"))
                tags = (side, tag)
            if it["mine"]:
                t.insert("end", " ", "mine_pad")
            t.insert("end", f" {it['text']} ", tags)
            t.insert("end", "\n")
            t.insert("end", "\n", "gap")
        t.see("end")
        t.config(state="disabled")

    def add_log(self, text, level="info"):
        self.log.config(state="normal")
        self.log.insert("end", f"[{time.strftime('%H:%M:%S')}] {text}\n\n", level)
        self.log.see("end")
        self.log.config(state="disabled")

    # ======================= ACTIONS =======================
    def send(self):
        text = self.entry.get().strip()
        if not text:
            return
        self.entry.delete(0, "end")
        try:
            if self.current == "group":
                self.client.send_group(text)
            else:
                self.client.send_dm(self.current, text)
        except OSError:
            self.ev_disconnected()

    def attach(self):
        if self.current == "group":
            return
        path = filedialog.askopenfilename(title=f"Send an encrypted file to {self.current}")
        if path:
            threading.Thread(target=self.client.send_file, args=(self.current, path), daemon=True).start()

    def on_close(self):
        if self.client:
            self.client.close()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    SecureChatApp(root)
    root.mainloop()
