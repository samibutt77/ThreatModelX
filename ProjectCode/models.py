import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from typing import List
from crypto_utils import encrypt_bytes, decrypt_bytes


DB_PATH = "users.db"

def init_user_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT,
        mfa_secret TEXT
    );
    """)
    conn.commit()
    conn.close()

class User:
    def __init__(self, id, username, password_hash, role, mfa_secret):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.mfa_secret = mfa_secret

    @staticmethod
    def exists(username):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT 1 FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        return row is not None

    @staticmethod
    def create(username, password, role, mfa_secret_plain):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        enc_secret = encrypt_bytes(mfa_secret_plain.encode('utf-8'))
        c.execute("INSERT INTO users (username, password_hash, role, mfa_secret) VALUES (?, ?, ?, ?)",
                  (username, generate_password_hash(password), role, enc_secret))
        conn.commit()
        conn.close()

    @staticmethod
    def _maybe_decrypt(value):
        # Try decrypt, fallback to plaintext
        try:
            return decrypt_bytes(value).decode('utf-8')
        except Exception:
            return value

    @staticmethod
    def get(username):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, username, password_hash, role, mfa_secret FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            id_, uname, pw_hash, role, enc_mfa = row
            mfa_plain = User._maybe_decrypt(enc_mfa)
            return User(id_, uname, pw_hash, role, mfa_plain)
        return None

    @staticmethod
    def get_by_id(uid):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, username, password_hash, role, mfa_secret FROM users WHERE id=?", (uid,))
        row = c.fetchone()
        conn.close()
        if row:
            id_, uname, pw_hash, role, enc_mfa = row
            mfa_plain = User._maybe_decrypt(enc_mfa)
            return User(id_, uname, pw_hash, role, mfa_plain)
        return None

    
       

class Component:
    def __init__(self, id: str, type: str, boundary: str = None):
        self.id = id
        self.type = type
        self.boundary = boundary

class DataStore:
    def __init__(self, id: str, type: str, boundary: str = None):
        self.id = id
        self.type = type
        self.boundary = boundary

class DataFlow:
    def __init__(self, source: str, target: str):
        self.source = source
        self.target = target

class SystemModel:
    def __init__(self):
        self.components: List[Component] = []
        self.datastores: List[DataStore] = []
        self.dataflows: List[DataFlow] = []

    def add_component(self, component: Component):
        self.components.append(component)

    def add_datastore(self, datastore: DataStore):
        self.datastores.append(datastore)

    def add_dataflow(self, dataflow: DataFlow):
        self.dataflows.append(dataflow)
