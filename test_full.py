"""test_full.py -- automated test of F1-F10.  Run: python test_full.py"""
import os, sys, threading, time
import server, hacker
from client import Client
from crypto_utils import decrypt

sys.argv = ["server.py", "5100"]
threading.Thread(target=server.main, daemon=True).start()
threading.Thread(target=hacker.proxy, args=(5101, "127.0.0.1", 5100), daemon=True).start()
time.sleep(0.5)
ok = lambda c, m: print(("PASS  " if c else "FAIL  ") + m) or (c or sys.exit(1))
has = lambda cl, s: any(s in l for l in cl.inbox)
wait = lambda: time.sleep(1.2)

a = Client("alice", port=5100, quiet=True); wait()
b = Client("bob", port=5100, quiet=True); wait()
c = Client("carol", port=5100, quiet=True); wait()
ok(a.cur_ver == b.cur_ver == c.cur_ver == 3, "F10 key rotated on each join (all at v3)")

a.handle_input("hello group"); wait()
ok(has(b, "[GROUP alice] hello group") and has(c, "[GROUP alice] hello group"), "F5 group chat")

a.handle_input("/dm bob secret for bob"); wait()
ok(has(b, "[DM alice] secret for bob"), "F4 DM delivered")
ok(not has(c, "secret for bob"), "F4 third user gets nothing")

open("t.txt", "wb").write(os.urandom(100000))
a.handle_input("/send bob t.txt"); wait()
ok(open("received/alice_t.txt", "rb").read() == open("t.txt", "rb").read(), "F9 file (4 chunks) identical")

a.handle_input("/fingerprint bob"); ok(has(a, "bob:"), "F8 fingerprint")

# F7: bob connects through the tampering proxy
d = Client("dave", port=5101, quiet=True); wait()
d.handle_input("/dm alice tampered?"); d.handle_input("group tamper test"); wait()
ok(has(a, "DM from dave failed integrity check"), "F7 tampered DM rejected")
ok(has(a, "group message from dave failed integrity check"), "F7 tampered group msg rejected")
d.close(); wait()

old = dict(c.group_keys)         # carol leaves; can she read what comes next?
c.close(); wait()
ver_before = a.cur_ver
a.handle_input("after carol left"); wait()
ok(a.cur_ver == ver_before and ver_before > 3, "F10 key rotated on leave")
ok(ver_before not in old, "carol (left) never received the new key, holds only " + str(sorted(old)))
ok(has(b, "[GROUP alice] after carol left"), "remaining members still chat after rotation")
print("\nALL TESTS PASSED")
