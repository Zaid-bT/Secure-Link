"""
hacker_gui.py -- F6 eavesdropper with a window.  Run:  python hacker_gui.py
Connects to the server as a silent sniffer and lists every relayed packet. It has no keys,
so the "Try to decrypt" button always fails: that is the proof of end-to-end encryption.
"""
import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk

from cryptography.fernet import Fernet, InvalidToken

from protocol import recv_msg, send_msg

BG, PANEL, FIELD = "#0f1420", "#171d2b", "#1f2638"
TEXT, MUTED, RED, GREEN, AMBER = "#e6e9f0", "#8b93a7", "#f87171", "#34d399", "#fbbf24"


class HackerApp:
    def __init__(self, root, host="127.0.0.1", port=5000):
        self.root, self.q, self.count, self.full = root, queue.Queue(), 0, {}
        root.title("Eavesdropper - what the attacker sees")
        root.geometry("1100x640")
        root.configure(bg=BG)
        st = ttk.Style()
        st.theme_use("clam")
        st.configure("Treeview", background=FIELD, fieldbackground=FIELD, foreground=TEXT,
                     rowheight=26, borderwidth=0, bordercolor=BG, lightcolor=BG, darkcolor=BG, font=("Consolas", 10))
        st.configure("Treeview.Heading", background=PANEL, foreground=MUTED, font=("Segoe UI", 9, "bold"), borderwidth=0)
        st.map("Treeview", background=[("selected", "#4a44c6")])

        top = tk.Frame(root, bg="#0a0e17", height=54)
        top.pack(fill="x")
        top.pack_propagate(False)
        tk.Label(top, text="\U0001F575  Eavesdropper", font=("Segoe UI", 14, "bold"), bg="#0a0e17", fg=RED).pack(side="left", padx=18)
        self.lbl_count = tk.Label(top, text="Packets intercepted: 0", font=("Segoe UI", 10, "bold"), bg="#0a0e17", fg=TEXT)
        self.lbl_count.pack(side="right", padx=18)
        self.lbl_state = tk.Label(top, text="connecting...", font=("Segoe UI", 10), bg="#0a0e17", fg=AMBER)
        self.lbl_state.pack(side="right", padx=8)

        cols = ("time", "type", "from", "to", "cipher", "status")
        self.tree = ttk.Treeview(root, columns=cols, show="headings", selectmode="browse")
        for c, w in zip(cols, (80, 90, 90, 90, 480, 150)):
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=14, pady=(14, 6))
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        det = tk.Frame(root, bg=PANEL, padx=14, pady=10)
        det.pack(fill="x", padx=14, pady=(0, 14))
        tk.Label(det, text="Selected packet (full ciphertext)", font=("Segoe UI", 9, "bold"), bg=PANEL, fg=MUTED).pack(anchor="w")
        self.detail = tk.Text(det, height=4, bg=FIELD, fg=AMBER, font=("Consolas", 10), relief="flat", wrap="char", highlightthickness=0)
        self.detail.pack(fill="x", pady=6)
        row = tk.Frame(det, bg=PANEL)
        row.pack(fill="x")
        tk.Button(row, text="Try to decrypt", command=self.try_decrypt, bg="#6c63ff", fg="white", relief="flat",
                  padx=14, pady=6, cursor="hand2", font=("Segoe UI", 10, "bold")).pack(side="left")
        self.lbl_result = tk.Label(row, text="", bg=PANEL, fg=MUTED, font=("Segoe UI", 10))
        self.lbl_result.pack(side="left", padx=12)

        self.tree.tag_configure("pk", foreground=MUTED)
        threading.Thread(target=self.listen, args=(host, port), daemon=True).start()
        root.after(100, self.poll)

    def listen(self, host, port):
        try:
            s = socket.create_connection((host, port))
            send_msg(s, {"type": "register", "from": "hacker", "to": "server", "data": {"role": "sniffer"}})
            recv_msg(s)
            self.q.put(("state", "listening"))
            while True:
                m = recv_msg(s)
                if m is None:
                    break
                self.q.put(("pkt", m))
        except OSError:
            pass
        self.q.put(("state", "disconnected"))

    def poll(self):
        try:
            while True:
                kind, v = self.q.get_nowait()
                if kind == "state":
                    self.lbl_state.config(text="\u25CF " + v, fg=GREEN if v == "listening" else RED)
                else:
                    self.add(v)
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def add(self, m):
        d = m.get("data")
        if m["type"] == "user_list":
            names = ", ".join(u["username"] for u in d)
            row = (time.strftime("%H:%M:%S"), "user_list", "server", "*", "public keys only: " + names, "public info")
            iid = self.tree.insert("", "end", values=row, tags=("pk",))
            self.full[iid] = None
        else:
            tok = d["token"] if isinstance(d, dict) else d
            row = (time.strftime("%H:%M:%S"), m["type"], m["from"], m["to"], tok[:80] + "...", "\U0001F512 UNREADABLE")
            iid = self.tree.insert("", "end", values=row)
            self.full[iid] = tok
            self.count += 1
            self.lbl_count.config(text=f"Packets intercepted: {self.count}")
        self.tree.see(iid)

    def on_select(self, _e):
        sel = self.tree.selection()
        tok = self.full.get(sel[0]) if sel else None
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", tok or "(no ciphertext: public keys are not secret)")
        self.lbl_result.config(text="")

    def try_decrypt(self):
        tok = self.detail.get("1.0", "end").strip()
        if not tok.startswith("gAAAA"):
            self.lbl_result.config(text="Select an encrypted packet first.", fg=MUTED)
            return
        try:
            Fernet(Fernet.generate_key()).decrypt(tok.encode())
        except InvalidToken:
            self.lbl_result.config(text="\u2718 FAILED - InvalidToken: the attacker has no key", fg=RED)


if __name__ == "__main__":
    r = tk.Tk()
    HackerApp(r)
    r.mainloop()
