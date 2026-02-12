import os
import sys
import json
import time
import getpass
import argparse
import shutil
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Import local modules refactored from the logic in the canvas
from core.security import RepoSecurity
from core.database import DatabaseManager
from core.manager import FileManager

# Environment Configuration
REPO_ROOT = os.getenv("REPO_ROOT", ".")
DB_PATH = os.path.join(REPO_ROOT, "repo.db")

# Initialize Managers
security = RepoSecurity(REPO_ROOT)
db = DatabaseManager(DB_PATH)

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
    with db.get_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM files"
        params = []
        if repo:
            query += " WHERE repo = ?"
            params.append(repo)
        rows = cursor.execute(query, params).fetchall()
        return [{**dict(row), "tags": json.loads(row["tags"]) if row["tags"] else []} for row in rows]

# --- Worker Logic ---
def process_pdf(pdf_path: str):
    if not HAS_PIKE: return False, "pikepdf not installed"
    try:
        with db.get_connection() as conn:
            creds_rows = conn.execute("SELECT encrypted_blob FROM credentials").fetchall()
            passwords = [security.decrypt_data(r['encrypted_blob']) for r in creds_rows]
        
        for pwd in passwords:
            try:
                with pikepdf.open(pdf_path, password=pwd) as pdf:
                    temp = pdf_path + ".tmp"
                    pdf.save(temp)
                    os.replace(temp, pdf_path)
                    return True, "Decrypted"
            except pikepdf.PasswordError: continue
        return False, "No valid password found"
    except Exception as e: return False, str(e)

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
                cursor.execute("UPDATE jobs SET status = 'PROCESSING' WHERE id = ?", (job_id,))
                conn.commit()

                success, msg = False, ""
                if job['job_type'] == 'DECRYPT_PDF':
                    success, msg = process_pdf(job['target_file'])
                
                new_status = 'COMPLETED' if success else ('FAILED' if job['attempts'] >= 5 else 'PENDING')
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
        print("--- Security Initialization ---")
        p = getpass.getpass("Create Master Password: ")
        security.initialize(p)
        print("Repo key generated and locked.")
    else:
        p = getpass.getpass("Unlock Repo Master Password: ")
        if not security.unlock(p):
            print("Authentication failed.")
            sys.exit(1)

def add_file(repo: str, path: str):
    """Processes a single file into the repository."""
    if not os.path.exists(path):
        print(f"Error: Path {path} does not exist.")
        return

    fid = FileManager.calculate_id(path)
    ftype = FileManager.get_type(path)
    filename = os.path.basename(path)
    
    target_dir = os.path.join(REPO_ROOT, repo, fid)
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, filename)
    shutil.copy2(path, target_path)
    
    with db.get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO files (id, name, repo, repo_path, tags) 
            VALUES (?, ?, ?, ?, ?)
        """, (fid, filename, repo, target_path, "[]"))
        
        if ftype == 'PDF':
            conn.execute("INSERT INTO jobs (job_type, target_file, file_id) VALUES (?, ?, ?)",
                         ('DECRYPT_PDF', target_path, fid))
        conn.commit()
    print(f"Successfully added [{ftype}] as {fid}")

def main():
    parser = argparse.ArgumentParser(description="RepoArch Unified CLI")
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

    # Ensure infrastructure is ready
    db.init_db()
    run_security_prompt()

    if args.cmd == "server":
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8000)
    elif args.cmd == "worker":
        run_worker()
    elif args.cmd == "add":
        add_file(args.repo, args.path)
    elif args.cmd == "init":
        os.makedirs(os.path.join(REPO_ROOT, args.name), exist_ok=True)
        print(f"Repository '{args.name}' initialized.")

if __name__ == "__main__":
    main()