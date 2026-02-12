import sqlite3
import os
import json
import base64
import getpass
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Configuration & Security ---
REPO_ROOT = os.getenv("REPO_ROOT", ".")
DB_PATH = os.path.join(REPO_ROOT, "repo.db")
CONFIG_PATH = os.path.join(REPO_ROOT, ".repo_config")

def get_master_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def initialize_repo_security():
    """Unlocks or initializes the REPO_KEY using a master password."""
    if not os.path.exists(REPO_ROOT):
        print(f"Making new folder {REPO_ROOT}")
        os.makedirs(REPO_ROOT)

    if not os.path.exists(CONFIG_PATH):
        print(f"Config path {CONFIG_PATH} does not exist")
        print("\n--- Initializing New Repository Security ---")
        password = getpass.getpass("Create a New Master Password: ")
        confirm = getpass.getpass("Confirm Master Password: ")
        if password != confirm:
            print("Passwords do not match. Initialization aborted.")
            exit(1)
        
        # Generate a fresh REPO_KEY and a salt
        new_repo_key = Fernet.generate_key()
        salt = os.urandom(16)
        
        # Encrypt the REPO_KEY with the master password
        master_fernet = Fernet(get_master_key(password, salt))
        encrypted_repo_key = master_fernet.encrypt(new_repo_key)
        
        # Store salt and encrypted key
        with open(CONFIG_PATH, "wb") as f:
            f.write(salt + b"||" + encrypted_repo_key)
        print("Success: REPO_KEY initialized and locked in repo.config.")
        return Fernet(new_repo_key)
    else:
        # Unlock existing key
        print("\n--- Repository Security Lock ---")
        password = getpass.getpass("Enter Master Password to unlock REPO_KEY: ")
        
        with open(CONFIG_PATH, "rb") as f:
            content = f.read()
            salt, encrypted_repo_key = content.split(b"||")
            
        try:
            master_fernet = Fernet(get_master_key(password, salt))
            decrypted_repo_key = master_fernet.decrypt(encrypted_repo_key)
            print("Success: REPO_KEY unlocked.")
            return Fernet(decrypted_repo_key)
        except Exception:
            print("Invalid Master Password. Access Denied.")
            exit(1)

# Unlock security before starting FastAPI
cipher_suite = initialize_repo_security()

app = FastAPI(title="RepoArch Backend")

# --- Middleware ---
# Add CORS support so the HTML dashboard can communicate with this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins, adjust for production security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Models ---
class CredentialCreate(BaseModel):
    password: str
    description: str

class FileUpdate(BaseModel):
    tags: List[str]

# --- Database Setup ---
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                repo TEXT NOT NULL,
                status TEXT DEFAULT 'ACTIVE',
                tags TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_blob TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_type TEXT NOT NULL,
                target_file TEXT NOT NULL,
                status TEXT DEFAULT 'PENDING',
                attempts INTEGER DEFAULT 0
            )
        ''')
        conn.commit()

init_db()

# --- API Endpoints ---

@app.get("/api/stats")
async def get_stats():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM files")
        total_files = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT repo) FROM files")
        total_repos = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM jobs WHERE status = 'PENDING'")
        pending_jobs = cursor.fetchone()[0]
        
    return {
        "total_files": total_files,
        "total_repos": total_repos,
        "pending_jobs": pending_jobs
    }

@app.get("/api/files")
async def get_files(repo: Optional[str] = None):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if repo:
            cursor.execute("SELECT * FROM files WHERE repo = ?", (repo,))
        else:
            cursor.execute("SELECT * FROM files")
        
        rows = cursor.fetchall()
        return [
            {**dict(row), "tags": json.loads(row["tags"]) if row["tags"] else []} 
            for row in rows
        ]

@app.post("/api/credentials")
async def add_credential(cred: CredentialCreate):
    # Encrypt using the unlocked REPO_KEY
    encrypted_pass = cipher_suite.encrypt(cred.password.encode()).decode()
    created_at = datetime.now().strftime("%Y-%m-%d")
    
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO credentials (encrypted_blob, description, created_at) VALUES (?, ?, ?)",
            (encrypted_pass, cred.description, created_at)
        )
        conn.commit()
        return {"status": "success", "id": cursor.lastrowid}

@app.get("/api/credentials")
async def get_credentials():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT id, description, created_at FROM credentials ORDER BY id DESC")
        return [dict(row) for row in cursor.fetchall()]

@app.get("/api/jobs")
async def get_jobs():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM jobs ORDER BY id DESC")
        return [dict(row) for row in cursor.fetchall()]

@app.delete("/api/files/{file_id}")
async def delete_file(file_id: str):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="File not found")
        return {"status": "deleted"}

if __name__ == "__main__":
    import uvicorn
    # Mock data for demonstration
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO files VALUES ('101', 'manual.pdf', 'Work', 'ACTIVE', '[\"Documentation\"]')")
        conn.commit()
        
    print(f"Database: {DB_PATH}")
    print(f"Config: {CONFIG_PATH}")
    print("Starting server on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)