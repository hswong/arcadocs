import sqlite3
import os
import json
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from cryptography.fernet import Fernet

app = FastAPI(title="RepoArch Backend")

# --- Configuration & Security ---
# In a production environment, REPO_KEY should be loaded from an environment variable
REPO_KEY = Fernet.generate_key() 
cipher_suite = Fernet(REPO_KEY)
DB_PATH = "repo_manager.db"

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
        # Files Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                repo TEXT NOT NULL,
                status TEXT DEFAULT 'ACTIVE',
                tags TEXT
            )
        ''')
        # Credentials Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_blob TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        # Jobs Table
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
    # Initial mock data for testing
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO files VALUES ('101', 'manual.pdf', 'Work', 'ACTIVE', '[\"Documentation\"]')")
        conn.commit()
        
    print("Starting server on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)