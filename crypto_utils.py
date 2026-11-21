"""
crypto_utils.py -- Member 2's F3 (keys), F4 (DM key), F8 (fingerprint) building blocks.
Private keys never leave client memory. Server only ever sees public keys + Fernet tokens.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------- F3: key generation ----------
def generate_keypair():
    """Returns (private_key_object, public_key_as_base64_string)."""
    priv = X25519PrivateKey.generate() #creates new randomm prvt key
    raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    
        #priv.publec_key() returns public key by matching it to the private key
        #public_bytes() returns the public key in 32 bytes (X25519 works on this format)

    return priv, base64.b64encode(raw).decode()
    #b64encode() turns bytes into base64 string, decode() turns bytes into string


# ---------- F4: one-to-one key ----------
def derive_dm_fernet(my_priv, peer_pub_b64: str) -> Fernet:
    """X25519 shared secret -> HKDF-SHA256 -> 32 bytes -> Fernet key."""
    #takes base64 string, decodes it to bytes and creates a public key object
    peer_pub = X25519PublicKey.from_public_bytes(base64.b64decode(peer_pub_b64))
    shared = my_priv.exchange(peer_pub) #A_prvt * B_pub == B_prvt * A_pub (same on both sides)
    key = HKDF(algorithm=hashes.SHA256(), length=32,
               salt=None, info=b"securechat-dm-v1").derive(shared)
    return Fernet(base64.urlsafe_b64encode(key))


# ---------- F8: fingerprint ----------
def fingerprint(pub_b64: str) -> str:
    """SHA-256 of the raw public key, shortened to 8 groups of 4 hex chars."""

    #decode public key back to raw bytes, hashes them (with sha256),
    #keeps first 32 hex chars (16 bytes) 
    h = hashlib.sha256(base64.b64decode(pub_b64)).hexdigest()[:32] 
    
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))
    #32 characters split into 8 grps of 4...
    #If a malicious server swaps B's key, the fingerprint A sees will differ from the one B sees.



# ---------- helpers used by F4/F5/F9 ----------
def encrypt(f: Fernet, plaintext: bytes) -> str:
    #plaintext coverted into encrypted token (by fernet encryption), 
    #encrypted token coverted to string datatype to be used by JSON msg
    return f.encrypt(plaintext).decode()


def decrypt(f: Fernet, token: str, ttl=None):
    """Returns plaintext bytes, or None if tampered / wrong key / too old (F7)."""
    try:
        return f.decrypt(token.encode(), ttl=ttl)
        #encode() converts string to bytes, decrypt() returns plaintext bytes
        #ttl allows older tokens to be rejected
    except InvalidToken:
        #integrity check before decryption
        return None #returning None instead of crashing so client.py prints warning msg and continue running.
