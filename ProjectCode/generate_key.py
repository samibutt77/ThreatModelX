# generate_key.py
import os, base64
k = os.urandom(32)
print(base64.b64encode(k).decode('utf-8'))
