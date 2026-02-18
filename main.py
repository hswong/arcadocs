import os
import sys
import json
import time
import getpass
import argparse
import shutil
import hashlib
import base64
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Import local modules from the core package
from core.security import RepoSecurity
from core.database import DatabaseManager
from core.manager import FileManager

# Environment Configuration
REPO_ROOT = os.getenv("REPO_ROOT", ".")
DB_PATH = os.path.join(REPO_ROOT, "repo.db")

# Initialize Managers
security = RepoSecurity(REPO_ROOT)
db = DatabaseManager(DB_PATH)

# Global debug flag
DEBUG_MODE = False

def debug_log(message: str):
    """Helper to print debug info if DEBUG_MODE is enabled."""
    if DEBUG_MODE:
        print(f"[DEBUG] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {message}")

# Check for PDF Support
try:
    import pikepdf
    HAS_PIKE = True
except ImportError:
    HAS_PIKE = False

# --- FastAPI Server Setup ---
app = FastAPI(title="RepoArch Modular API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class CredentialCreate(BaseModel):
    password: str
    description: str

@app.get("/api/stats")
async def get_stats():
    debug_log("Fetching repository statistics.")
    with db.get_connection() as conn:
        cursor = conn.cursor()
        res = cursor.execute("""
            SELECT 
                (SELECT COUNT(*) FROM files) as total_files,
                (SELECT COUNT(DISTINCT repo) FROM files) as total_repos,
                (SELECT COUNT(*) FROM jobs WHERE status = 'PENDING') as pending_jobs
        """).fetchone()
    return dict(res)

@app.get("/api/files")
async def get_files(repo: Optional[str] = None):
    debug_log(f"Fetching files. Filter repo: {repo}")
    with db.get_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM files"
        params = []
        if repo:
            query += " WHERE repo = ?"
            params.append(repo)
        rows = cursor.execute(query, params).fetchall()
        return [{**dict(row), "tags": json.loads(row["tags"]) if row["tags"] else []} for row in rows]

@app.get("/api/credentials")
async def get_credentials():
    """Returns stored credentials, decrypted for UI display."""
    debug_log("Fetching credentials.")
    try:
        with db.get_connection() as conn:
            rows = conn.execute("SELECT id, description, encrypted_blob, created_at FROM credentials").fetchall()
            results = []
            for row in rows:
                decrypted_val = security.decrypt_data(row["encrypted_blob"])
                results.append({
                    "id": row["id"],
                    "description": row["description"],
                    "value": decrypted_val,
                    "created_at": row["created_at"]
                })
            return results
    except Exception as e:
        debug_log(f"Error fetching credentials: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve credentials")

@app.get("/api/jobs")
async def get_jobs():
    """Returns the current background job queue."""
    debug_log("Fetching job queue.")
    with db.get_connection() as conn:
        # Note: Removing created_at and updated_at to match current schema
        rows = conn.execute("""
            SELECT id, job_type, status, attempts, last_error
            FROM jobs 
            ORDER BY id DESC
        """).fetchall()
        return [dict(row) for row in rows]

# --- Worker Logic ---
def process_pdf(pdf_path: str):
    debug_log(f"Attempting PDF decryption for: {pdf_path}")
    if not HAS_PIKE: 
        debug_log("pikepdf not available.")
        return False, "pikepdf not installed"
    try:
        with db.get_connection() as conn:
            creds_rows = conn.execute("SELECT encrypted_blob FROM credentials").fetchall()
            passwords = [security.decrypt_data(r['encrypted_blob']) for r in creds_rows]
        
        debug_log(f"Testing {len(passwords)} stored credentials.")
        for pwd in passwords:
            try:
                with pikepdf.open(pdf_path, password=pwd) as pdf:
                    temp = pdf_path + ".tmp"
                    pdf.save(temp)
                    os.replace(temp, pdf_path)
                    debug_log("Decryption successful.")
                    return True, "Decrypted"
            except pikepdf.PasswordError: continue
        
        debug_log("No matching password found in database.")
        return False, "No valid password found"
    except Exception as e: 
        debug_log(f"PDF processing error: {e}")
        return False, str(e)

def run_worker():
    print(f"Worker active. Monitoring {DB_PATH}...")
    while True:
        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                job = cursor.execute("SELECT * FROM jobs WHERE status = 'PENDING' LIMIT 1").fetchone()
                if not job:
                    time.sleep(5)
                    continue
                
                job_id = job['id']
                debug_log(f"Processing job ID: {job_id} | Type: {job['job_type']}")
                cursor.execute("UPDATE jobs SET status = 'PROCESSING' WHERE id = ?", (job_id,))
                conn.commit()

                success, msg = False, ""
                if job['job_type'] == 'DECRYPT_PDF':
                    success, msg = process_pdf(job['target_file'])
                
                new_status = 'COMPLETED' if success else ('FAILED' if job['attempts'] >= 5 else 'PENDING')
                debug_log(f"Job result: {new_status} | Info: {msg}")
                cursor.execute("""
                    UPDATE jobs 
                    SET status = ?, attempts = attempts + 1, last_error = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE id = ?
                """, (new_status, msg, job_id))
                conn.commit()
        except Exception as e:
            print(f"Worker error: {e}")
            time.sleep(5)

# --- CLI Orchestration ---
def run_security_prompt():
    """Initializes or unlocks the encryption layer via CLI."""
    if not security.is_initialized():
        debug_log("Security config (.repo_config) not found. Prompting for initialization.")
        print("--- Security Initialization ---")
        p = getpass.getpass("Create Master Password: ")
        security.initialize(p)
        print("Repo key generated and locked in .repo_config.")
    else:
        debug_log("Security config (.repo_config) found. Prompting for unlock.")
        p = getpass.getpass("Unlock Repo Master Password: ")
        if not security.unlock(p):
            print("Authentication failed.")
            sys.exit(1)
        debug_log("Security layer unlocked successfully.")

def add_file(repo: str, path: str):
    """Processes a single file into the repository."""
    debug_log(f"Scanning source path: {path}")
    if not os.path.exists(path):
        print(f"Error: Path {path} does not exist.")
        return

    fid = FileManager.calculate_id(path)
    ftype = FileManager.get_type(path)
    filename = os.path.basename(path)
    debug_log(f"File ID: {fid} | Type: {ftype}")
    
    target_dir = os.path.join(REPO_ROOT, repo, fid)
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, filename)
    debug_log(f"Copying to: {target_path}")
    shutil.copy2(path, target_path)
    
    with db.get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO files (id, name, repo, repo_path, tags) 
            VALUES (?, ?, ?, ?, ?)
        """, (fid, filename, repo, target_path, "[]"))
        
        if ftype == 'PDF':
            debug_log("PDF detected. Queueing decryption job.")
            conn.execute("INSERT INTO jobs (job_type, target_file, file_id) VALUES (?, ?, ?)",
                         ('DECRYPT_PDF', target_path, fid))
        conn.commit()
    print(f"Successfully added [{ftype}] as {fid}")

def main():
    global DEBUG_MODE
    parser = argparse.ArgumentParser(description="RepoArch Unified CLI")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output")
    
    sub = parser.add_subparsers(dest="cmd")
    
    sub.add_parser("server", help="Run the FastAPI web server")
    sub.add_parser("worker", help="Run the background job processor")
    
    add_parser = sub.add_parser("add", help="Add a file to a repository")
    add_parser.add_argument("repo", help="Target repository name")
    add_parser.add_argument("path", help="Path to the source file")
    
    init_parser = sub.add_parser("init", help="Initialize a new repository directory")
    init_parser.add_argument("name")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return

    if args.debug:
        DEBUG_MODE = True
        debug_log("Debug mode enabled.")
        debug_log(f"REPO_ROOT: {os.path.abspath(REPO_ROOT)}")
        debug_log(f"DB_PATH: {os.path.abspath(DB_PATH)}")
        debug_log(f"Python Version: {sys.version.split()[0]}")
        debug_log(f"PDF Support (pikepdf): {'Available' if HAS_PIKE else 'Missing'}")

    # Ensure infrastructure is ready
    db.init_db()

    run_security_prompt()

    if args.cmd == "server":
        debug_log("Starting uvicorn server...")
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8000)
    elif args.cmd == "worker":
        run_worker()
    elif args.cmd == "add":
        add_file(args.repo, args.path)
    elif args.cmd == "init":
        path = os.path.join(REPO_ROOT, args.name)
        os.makedirs(path, exist_ok=True)
        debug_log(f"Created directory: {path}")
        print(f"Repository '{args.name}' initialized.")

if __name__ == "__main__":
    main()