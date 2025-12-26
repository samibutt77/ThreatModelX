# crypto_utils.py
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Expect MASTER_KEY as base64-encoded 32 bytes
def _get_key() -> bytes:
    b64 = os.environ.get("MASTER_KEY")
    if not b64:
        raise RuntimeError("MASTER_KEY env var not set. Generate with: python generate_key.py")
    key = base64.b64decode(b64)
    if len(key) != 32:
        raise RuntimeError("MASTER_KEY must decode to 32 bytes (256 bits)")
    return key

def encrypt_bytes(plaintext: bytes) -> str:
    """
    Encrypt bytes with AES-256-GCM.
    Returns base64(nonce + ciphertext + tag).
    """
    key = _get_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # recommended 96-bit nonce
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    blob = nonce + ct
    return base64.b64encode(blob).decode('utf-8')

def decrypt_bytes(b64_blob: str) -> bytes:
    """
    Decrypt base64(nonce + ciphertext + tag) and return plaintext bytes.
    """
    key = _get_key()
    aesgcm = AESGCM(key)
    blob = base64.b64decode(b64_blob)
    nonce = blob[:12]
    ct = blob[12:]
    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
    return pt
