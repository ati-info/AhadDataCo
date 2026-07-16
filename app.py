import os
import sqlite3
import secrets
import hashlib
import time
from datetime import datetime, timedelta
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Header, Depends, Form, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import bcrypt
import pyotp
import qrcode
import io
import base64

# ==================== FREE PLAN SAFE ====================
DB_PATH = os.getenv("DB_PATH", "/tmp/database.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", "10"))
BREVO_API_KEY = os.getenv("BREVO_API_KEY", "").strip()
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "").strip()
SENDER_NAME = os.getenv("SENDER_NAME", "Ahad Co")

app = FastAPI(title="Ahad Co Auth System")
app.mount("/static", StaticFiles(directory="static"), name="static")

# ==================== SAFE get_db() ====================
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def close_db(conn):
    if conn:
        conn.commit()
        conn.close()

# ==================== INIT DB ====================
def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            phone TEXT,
            custom_code TEXT,
            role TEXT DEFAULT 'user',
            is_verified INTEGER DEFAULT 0,
            otp TEXT,
            otp_created_at TEXT,
            twofa_enabled INTEGER DEFAULT 0,
            twofa_secret TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            label TEXT NOT NULL,
            value TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT,
            color TEXT DEFAULT '#1f2937',
            pinned INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS bookmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            description TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS twofa_backup_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    close_db(conn)
    print(f"✅ Database initialized successfully at {DB_PATH}")

init_db()

# ==================== HELPERS ====================
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def generate_token():
    return secrets.token_hex(32)

def generate_otp() -> str:
    return f"{secrets.randbelow(1000000):06d}"

def send_otp_email(email: str, otp: str, username: str):
    """Send OTP via Brevo if keys are set, otherwise log it (for testing)."""
    if not BREVO_API_KEY or not SENDER_EMAIL:
        # Free plan / testing mode - log OTP
        print(f"⚠️  [TEST MODE] OTP for {email} ({username}): {otp}")
        print("   (Set BREVO_API_KEY and SENDER_EMAIL in Render env to send real emails)")
        return

    try:
        import requests
        headers = {
            "accept": "application/json",
            "api-key": BREVO_API_KEY,
            "content-type": "application/json"
        }
        payload = {
            "sender": {"name": SENDER_NAME, "email": SENDER_EMAIL},
            "to": [{"email": email}],
            "subject": "Your Ahad Co Verification Code",
            "textContent": f"Hello {username},\n\nYour verification code is: {otp}\n\nThis code expires in {OTP_EXPIRY_MINUTES} minutes.\n\n— Ahad Co",
            "htmlContent": f"""
            <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;">
                <h2>Ahad Co Verification</h2>
                <p>Hello <strong>{username}</strong>,</p>
                <p>Your verification code is:</p>
                <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; background: #f3f4f6; padding: 16px; text-align: center; border-radius: 8px;">
                    {otp}
                </div>
                <p style="color: #666;">This code expires in {OTP_EXPIRY_MINUTES} minutes.</p>
                <hr>
                <p style="font-size: 12px; color: #999;">— Ahad Co</p>
            </div>
            """
        }
        response = requests.post("https://api.brevo.com/v3/smtp/email", json=payload, headers=headers, timeout=15)
        if response.status_code not in (200, 201, 202):
            print("Brevo error:", response.text)
    except Exception as e:
        print("Email send failed (non-fatal):", str(e))

def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Invalid token")
    
    token = authorization.split(" ")[1]
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM sessions WHERE token = ?", (token,))
    session = cursor.fetchone()
    
    if not session:
        close_db(conn)
        raise HTTPException(401, "Session not found")
    
    cursor.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
    user = cursor.fetchone()
    
    close_db(conn)
    
    if not user:
        raise HTTPException(401, "User not found")
    
    return dict(user)

# ==================== AUTH ENDPOINTS ====================
@app.post("/signup")
async def signup(data: dict):
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    phone = data.get("phone")
    
    if not username or not email or not password:
        raise HTTPException(400, "Missing fields")
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM users WHERE email = ? OR username = ?", (email, username))
    if cursor.fetchone():
        close_db(conn)
        raise HTTPException(400, "Email or username already registered")
    
    hashed = hash_password(password)
    otp = generate_otp()
    now = datetime.now().isoformat()
    
    cursor.execute("""
        INSERT INTO users (username, email, password, phone, otp, otp_created_at, is_verified)
        VALUES (?, ?, ?, ?, ?, ?, 0)
    """, (username, email, hashed, phone, otp, now))
    
    close_db(conn)
    
    send_otp_email(email, otp, username)
    
    return {"message": "Account created. Check your email for the verification code."}

@app.post("/resend-otp")
async def resend_otp(data: dict):
    identifier = data.get("email") or data.get("username")
    if not identifier:
        raise HTTPException(400, "Email or username required")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ? OR username = ?", (identifier, identifier))
    user = cursor.fetchone()
    
    if not user:
        close_db(conn)
        return {"message": "If the account exists, a new code was sent."}
    
    if user["is_verified"]:
        close_db(conn)
        return {"message": "Account already verified."}
    
    otp = generate_otp()
    now = datetime.now().isoformat()
    cursor.execute("UPDATE users SET otp = ?, otp_created_at = ? WHERE id = ?", (otp, now, user["id"]))
    close_db(conn)
    
    send_otp_email(user["email"], otp, user["username"])
    return {"message": "New code sent to your email."}

@app.post("/login")
async def login(data: dict):
    email = data.get("email") or data.get("username")  # support both
    password = data.get("password")
    totp_code = data.get("totp_code")
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE email = ? OR username = ?", (email, email))
    user = cursor.fetchone()
    
    if not user or not verify_password(password, user["password"]):
        close_db(conn)
        raise HTTPException(401, "Invalid credentials")
    
    if not user["is_verified"]:
        close_db(conn)
        raise HTTPException(403, "Please verify your email first")
    
    # 2FA check
    if user["twofa_enabled"]:
        if not totp_code:
            close_db(conn)
            raise HTTPException(401, "2FA code required")
        
        totp = pyotp.TOTP(user["twofa_secret"])
        if not totp.verify(totp_code):
            # Check backup codes
            cursor.execute("SELECT code FROM twofa_backup_codes WHERE user_id = ? AND used = 0", (user["id"],))
            backup_codes = [row["code"] for row in cursor.fetchall()]
            if totp_code not in backup_codes:
                close_db(conn)
                raise HTTPException(401, "Invalid 2FA code")
            cursor.execute("UPDATE twofa_backup_codes SET used = 1 WHERE user_id = ? AND code = ?", (user["id"], totp_code))
    
    token = generate_token()
    cursor.execute("INSERT INTO sessions (user_id, token) VALUES (?, ?)", (user["id"], token))
    
    close_db(conn)
    return {"token": token, "message": "Login successful"}

@app.post("/verify")
async def verify(data: dict):
    identifier = data.get("email") or data.get("username")
    otp = str(data.get("otp", "")).strip()
    
    if not identifier:
        raise HTTPException(400, "Email or username required")
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE email = ? OR username = ?", (identifier, identifier))
    user = cursor.fetchone()
    
    if not user:
        close_db(conn)
        raise HTTPException(404, "User not found")
    
    if not user.get("otp"):
        close_db(conn)
        raise HTTPException(400, "No OTP found. Please click Resend Code.")
    
    # Check expiry
    try:
        if user.get("otp_created_at"):
            otp_time = datetime.fromisoformat(user["otp_created_at"])
            if (datetime.now() - otp_time).total_seconds() > (OTP_EXPIRY_MINUTES * 60):
                close_db(conn)
                raise HTTPException(400, "OTP expired. Please request a new code.")
    except Exception:
        pass
    
    if str(user["otp"]) != otp:
        close_db(conn)
        raise HTTPException(400, "Invalid verification code")
    
    cursor.execute("""
        UPDATE users SET is_verified = 1, otp = NULL, otp_created_at = NULL 
        WHERE id = ?
    """, (user["id"],))
    close_db(conn)
    
    return {"message": "Account verified successfully!"}

# ==================== VAULT ====================
@app.get("/vault")
async def get_vault(user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vault_entries WHERE user_id = ? ORDER BY created_at DESC", (user["id"],))
    entries = [dict(row) for row in cursor.fetchall()]
    close_db(conn)
    return {"entries": entries}

@app.post("/vault/add")
async def add_vault(data: dict, user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO vault_entries (user_id, type, label, value)
        VALUES (?, ?, ?, ?)
    """, (user["id"], data["type"], data["label"], data.get("value")))
    close_db(conn)
    return {"message": "Vault entry added"}

@app.post("/vault/update/{entry_id}")
async def update_vault(entry_id: int, data: dict, user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE vault_entries SET label = ?, value = ?
        WHERE id = ? AND user_id = ?
    """, (data["label"], data.get("value"), entry_id, user["id"]))
    close_db(conn)
    return {"message": "Updated"}

@app.delete("/vault/delete/{entry_id}")
async def delete_vault(entry_id: int, user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault_entries WHERE id = ? AND user_id = ?", (entry_id, user["id"]))
    close_db(conn)
    return {"message": "Deleted"}

# ==================== NOTES ====================
@app.get("/notes")
async def get_notes(user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notes WHERE user_id = ? ORDER BY pinned DESC, created_at DESC", (user["id"],))
    notes = [dict(row) for row in cursor.fetchall()]
    close_db(conn)
    return {"notes": notes}

@app.post("/notes")
async def create_note(data: dict, user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO notes (user_id, title, content, color, pinned)
        VALUES (?, ?, ?, ?, 0)
    """, (user["id"], data["title"], data.get("content"), data.get("color", "#1f2937")))
    close_db(conn)
    return {"message": "Note created"}

@app.put("/notes/{note_id}")
async def update_note(note_id: int, data: dict, user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE notes SET title = ?, content = ?, color = ?
        WHERE id = ? AND user_id = ?
    """, (data["title"], data.get("content"), data.get("color"), note_id, user["id"]))
    close_db(conn)
    return {"message": "Note updated"}

@app.put("/notes/{note_id}/pin")
async def pin_note(note_id: int, user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE notes SET pinned = 1 - pinned WHERE id = ? AND user_id = ?", (note_id, user["id"]))
    close_db(conn)
    return {"message": "Toggled pin"}

@app.delete("/notes/{note_id}")
async def delete_note(note_id: int, user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, user["id"]))
    close_db(conn)
    return {"message": "Note deleted"}

# ==================== BOOKMARKS ====================
@app.get("/bookmarks")
async def get_bookmarks(user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM bookmarks WHERE user_id = ? ORDER BY created_at DESC", (user["id"],))
    bookmarks = [dict(row) for row in cursor.fetchall()]
    close_db(conn)
    return {"bookmarks": bookmarks}

@app.post("/bookmarks")
async def add_bookmark(data: dict, user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO bookmarks (user_id, title, url, description)
        VALUES (?, ?, ?, ?)
    """, (user["id"], data["title"], data["url"], data.get("description")))
    close_db(conn)
    return {"message": "Bookmark saved"}

@app.delete("/bookmarks/{bookmark_id}")
async def delete_bookmark(bookmark_id: int, user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM bookmarks WHERE id = ? AND user_id = ?", (bookmark_id, user["id"]))
    close_db(conn)
    return {"message": "Bookmark deleted"}

# ==================== PROFILE ====================
@app.get("/profile")
async def get_profile(user=Depends(get_current_user)):
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "phone": user.get("phone"),
        "custom_code": user.get("custom_code"),
        "twofa_enabled": bool(user.get("twofa_enabled"))
    }

@app.post("/profile/update")
async def update_profile(data: dict, user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users SET username = ?, phone = ?, custom_code = ?
        WHERE id = ?
    """, (data.get("username"), data.get("phone"), data.get("custom_code"), user["id"]))
    close_db(conn)
    return {"message": "Profile updated"}

# ==================== 2FA ====================
@app.post("/2fa/setup")
async def setup_2fa(user=Depends(get_current_user)):
    if user.get("twofa_enabled"):
        raise HTTPException(400, "2FA already enabled")
    
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user["email"], issuer_name="Ahad Co")
    
    # Generate QR
    qr = qrcode.make(uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()
    
    # Generate backup codes
    backup_codes = [secrets.token_hex(4) for _ in range(8)]
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET twofa_secret = ? WHERE id = ?", (secret, user["id"]))
    
    cursor.execute("DELETE FROM twofa_backup_codes WHERE user_id = ?", (user["id"],))
    for code in backup_codes:
        cursor.execute("INSERT INTO twofa_backup_codes (user_id, code) VALUES (?, ?)", (user["id"], code))
    
    close_db(conn)
    
    return {
        "secret": secret,
        "qr_code": f"data:image/png;base64,{qr_b64}",
        "backup_codes": backup_codes
    }

@app.post("/2fa/verify-setup")
async def verify_2fa_setup(data: dict = None, code: str = Form(...), user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT twofa_secret FROM users WHERE id = ?", (user["id"],))
    row = cursor.fetchone()
    secret = row["twofa_secret"] if row else None
    
    if not secret:
        close_db(conn)
        raise HTTPException(400, "2FA not set up")
    
    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        cursor.execute("UPDATE users SET twofa_enabled = 1 WHERE id = ?", (user["id"],))
        close_db(conn)
        return {"message": "2FA enabled"}
    
    close_db(conn)
    raise HTTPException(400, "Invalid code")

@app.get("/2fa/status")
async def twofa_status(user=Depends(get_current_user)):
    return {"enabled": bool(user.get("twofa_enabled"))}

# ==================== ACCOUNT DELETE ====================
@app.post("/account/delete")
async def delete_account(password: str = Form(...), user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT password FROM users WHERE id = ?", (user["id"],))
    row = cursor.fetchone()
    
    if not row or not verify_password(password, row["password"]):
        close_db(conn)
        raise HTTPException(401, "Incorrect password")
    
    cursor.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    close_db(conn)
    
    return {"message": "Account deleted permanently"}

# ==================== LOGOUT ====================
@app.post("/logout")
async def logout(user=Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    close_db(conn)
    return {"message": "Logged out"}

# ==================== BASIC ROUTES ====================
@app.get("/health")
def health():
    return {"status": "ok", "db": "sqlite", "path": DB_PATH}

@app.get("/")
def root():
    return HTMLResponse(open("index.html").read())

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)