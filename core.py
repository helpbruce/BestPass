# secure_core_v4.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
import os
import base64
import secrets
import string
import datetime
import pyotp

app = FastAPI(title="Secure Password Manager Core v4")

DB_FILE = "passwords.db"
CONFIG_FILE = "config.bin"
ph = PasswordHasher(time_cost=2, memory_cost=51200, parallelism=2, hash_len=32)

# --- Инициализация БД ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
                 (id INTEGER PRIMARY KEY, name TEXT, login TEXT, password TEXT)''')
    conn.commit()
    conn.close()
init_db()

# --- Модели API ---
class MasterPassword(BaseModel):
    master: str

class PasswordEntry(BaseModel):
    name: str
    login: str
    password: str
    master: str
    totp_code: str = None

class PasswordUpdate(BaseModel):
    id: int
    name: str = None
    login: str = None
    password: str = None
    master: str = None
    totp_code: str = None

class KeyRotation(BaseModel):
    master: str
    rotation_days: int  # 7/30/90

# --- Функции генерации ключей и одноразового пароля ---
def generate_key(master_password: str, salt: bytes) -> bytes:
    return ph.hash(master_password + salt.hex()).encode()[:32]

def generate_word(length=5):
    return ''.join(secrets.choice(string.ascii_lowercase) for _ in range(length))

def generate_one_time_password(num_words=22, min_len=5, max_len=7):
    return [generate_word(secrets.choice(range(min_len, max_len+1))) for _ in range(num_words)]

def init_master(master_password: str):
    if os.path.exists(CONFIG_FILE):
        raise Exception("Master password уже установлен")
    salt = os.urandom(16)
    key = generate_key(master_password, salt)
    # Генерация одноразового пароля (22 слова, случайно)
    recovery = generate_one_time_password()
    totp_secret = pyotp.random_base32()
    config_data = {
        "salt": salt.hex(),
        "last_key_rotation": datetime.datetime.utcnow().isoformat(),
        "recovery": recovery,
        "totp_secret": totp_secret
    }
    with open(CONFIG_FILE, "wb") as f:
        f.write(str(config_data).encode())
    return key, recovery, totp_secret

def verify_master(master_password: str):
    if not os.path.exists(CONFIG_FILE):
        raise Exception("Master password не установлен")
    with open(CONFIG_FILE, "rb") as f:
        config_data = eval(f.read().decode())
    salt = bytes.fromhex(config_data["salt"])
    key = generate_key(master_password, salt)
    return key, config_data

def check_2fa(config_data, totp_code):
    if config_data.get("totp_secret"):
        if not totp_code:
            raise HTTPException(status_code=403, detail="2FA code required")
        totp = pyotp.TOTP(config_data["totp_secret"])
        if not totp.verify(totp_code):
            raise HTTPException(status_code=403, detail="Invalid 2FA code")

# --- API ---
@app.post("/init_master")
def api_init_master(master: MasterPassword):
    try:
        key, recovery, totp_secret = init_master(master.master)
        return {
            "status": "Master password set",
            "recovery_phrase": recovery,
            "totp_secret": totp_secret
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/add")
def add_password(entry: PasswordEntry):
    try:
        key, config_data = verify_master(entry.master)
        check_2fa(config_data, entry.totp_code)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted_password = aesgcm.encrypt(nonce, entry.password.encode(), None)
        stored = base64.b64encode(nonce + encrypted_password).decode()
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO passwords (name, login, password) VALUES (?, ?, ?)",
                  (entry.name, entry.login, stored))
        conn.commit()
        conn.close()
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/get/{name}")
def get_password(name: str, master: str, totp_code: str = None):
    try:
        key, config_data = verify_master(master)
        check_2fa(config_data, totp_code)
        aesgcm = AESGCM(key)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, login, password FROM passwords WHERE name=?", (name,))
        row = c.fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=404, detail="Password not found")
        id_, login, stored = row
        decoded = base64.b64decode(stored.encode())
        nonce, encrypted_password = decoded[:12], decoded[12:]
        password = aesgcm.decrypt(nonce, encrypted_password, None).decode()
        return {"id": id_, "login": login, "password": password}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/update")
def update_password(entry: PasswordUpdate):
    try:
        key, config_data = verify_master(entry.master)
        check_2fa(config_data, entry.totp_code)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT name, login, password FROM passwords WHERE id=?", (entry.id,))
        row = c.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Password not found")
        name_old, login_old, stored_old = row
        aesgcm = AESGCM(key)
        decoded = base64.b64decode(stored_old.encode())
        nonce, encrypted_password = decoded[:12], decoded[12:]
        password_plain = aesgcm.decrypt(nonce, encrypted_password, None)
        # Обновление полей
        name_new = entry.name or name_old
        login_new = entry.login or login_old
        password_new = entry.password.encode() if entry.password else password_plain
        nonce_new = os.urandom(12)
        encrypted_new = aesgcm.encrypt(nonce_new, password_new, None)
        stored_new = base64.b64encode(nonce_new + encrypted_new).decode()
        c.execute("UPDATE passwords SET name=?, login=?, password=? WHERE id=?",
                  (name_new, login_new, stored_new, entry.id))
        conn.commit()
        conn.close()
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/delete/{id}")
def delete_password(id: int, master: str, totp_code: str = None):
    try:
        key, config_data = verify_master(master)
        check_2fa(config_data, totp_code)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM passwords WHERE id=?", (id,))
        conn.commit()
        conn.close()
        return {"status": "deleted"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/list")
def list_passwords(master: str, totp_code: str = None):
    try:
        key, config_data = verify_master(master)
        check_2fa(config_data, totp_code)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, name, login FROM passwords")
        rows = c.fetchall()
        conn.close()
        return [{"id": r[0], "name": r[1], "login": r[2]} for r in rows]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/rotate_keys")
def rotate_keys(rotation: KeyRotation):
    try:
        key, config_data = verify_master(rotation.master)
        now = datetime.datetime.utcnow()
        last = datetime.datetime.fromisoformat(config_data["last_key_rotation"])
        delta = (now - last).days
        if delta < rotation.rotation_days:
            return {"status": f"Next rotation in {rotation.rotation_days - delta} days"}
        aesgcm_new = AESGCM(generate_key(rotation.master, os.urandom(16)))
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, password FROM passwords")
        rows = c.fetchall()
        for row in rows:
            id_, stored = row
            decoded = base64.b64decode(stored.encode())
            nonce_old, encrypted_password = decoded[:12], decoded[12:]
            password_plain = AESGCM(key).decrypt(nonce_old, encrypted_password, None)
            nonce_new = os.urandom(12)
            encrypted_new = aesgcm_new.encrypt(nonce_new, password_plain, None)
            stored_new = base64.b64encode(nonce_new + encrypted_new).decode()
            c.execute("UPDATE passwords SET password=? WHERE id=?", (stored_new, id_))
        conn.commit()
        conn.close()
        config_data["last_key_rotation"] = now.isoformat()
        with open(CONFIG_FILE, "wb") as f:
            f.write(str(config_data).encode())
        return {"status": "Keys rotated successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
