import os
import sys
import json
import time
import getpass
import argparse
import shutil
import hashlib
import base64
import threading
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional, Dict, Type, Tuple, List, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

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

# Global State for Integrated Worker
worker_thread = None
worker_active = False
DEBUG_MODE = False

def debug_log(message: str):
    """Helper to print debug info ONLY if DEBUG_MODE is enabled."""
    if DEBUG_MODE:
        print(f"[DEBUG] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {message}")
        sys.stdout.flush()

# Check for PDF Support
try:
    import pikepdf
    HAS_PIKE = True
except ImportError:
    HAS_PIKE = False

# --- Models ---

class WorkflowConfig(BaseModel):
    rules: Dict[str, List[str]]

class CredentialCreate(BaseModel):
    # Use Field to ensure 'value' is mapped correctly even if sent as 'credential_value'
    value: str = Field(..., alias="value")
    description: Optional[str] = ""

    class Config:
        populate_by_name = True

# --- Plugin/Dynamic Logic System ---

class BaseJobHandler:
    """Base class for all worker job logic."""
    @staticmethod
    def process(job_data: dict) -> Tuple[bool, str]:
        raise NotImplementedError("Handlers must implement process()")

class UnzipHandler(BaseJobHandler):
    @staticmethod
    def process(job_data: dict) -> Tuple[bool, str]:
        zip_path = job_data['target_file']
        repo_name = job_data['repo']
        debug_log(f"Handling UNZIP for: {zip_path}")
        extract_to = zip_path + "_extracted"
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
            
            extracted_count = 0
            for root, _, files in os.walk(extract_to):
                for f in files:
                    child_src = os.path.join(root, f)
                    # Process each extracted file as a fresh addition to the repo
                    add_file(repo_name, child_src)
                    extracted_count += 1
            
            shutil.rmtree(extract_to)
            return True, f"Extracted and processed {extracted_count} files."
        except Exception as e:
            if os.path.exists(extract_to):
                shutil.rmtree(extract_to)
            return False, str(e)

class PDFDecryptHandler(BaseJobHandler):
    @staticmethod
    def process(job_data: dict) -> Tuple[bool, str]:
        pdf_path = job_data['target_file']
        repo_name = job_data['repo']
        debug_log(f"Attempting PDF processing for: {pdf_path}")
        
        if not HAS_PIKE: 
            return False, "pikepdf not installed"
        
        try:
            # Determine path for the decrypted version
            base_dir = os.path.dirname(pdf_path)
            output_dir = os.path.join(base_dir, "DECRYPT_TEMP")
            os.makedirs(output_dir, exist_ok=True)
            
            filename = os.path.basename(pdf_path)
            # Use a prefix to distinguish from original in case of same directory
            decrypted_filename = f"decrypted_{filename}"
            output_path = os.path.join(output_dir, decrypted_filename)
            
            is_encrypted = False
            decryption_successful = False

            # 1. Check if the PDF is actually encrypted
            try:
                with pikepdf.open(pdf_path) as pdf:
                    debug_log("PDF is not encrypted. Skipping decryption workflow.")
                    # No new file needed if it's already openable
                    return True, "PDF already accessible."
            except pikepdf.PasswordError:
                is_encrypted = True
                debug_log("PDF is password protected. Searching credentials...")

            # 2. Try to unlock with stored credentials
            with db.get_connection() as conn:
                creds_rows = conn.execute("SELECT encrypted_blob FROM credentials").fetchall()
                passwords = [security.decrypt_data(r['encrypted_blob']) for r in creds_rows]
            
            for pwd in passwords:
                try:
                    with pikepdf.open(pdf_path, password=pwd) as pdf:
                        pdf.save(output_path)
                        debug_log(f"Decryption successful with a stored password.")
                        decryption_successful = True
                        break
                except pikepdf.PasswordError:
                    continue

            # 3. If successfully decrypted, add as a NEW file to the repo
            if decryption_successful:
                add_file(repo_name, output_path)
                # Cleanup temporary decrypted file after add_file has copied it to its permanent location
                if os.path.exists(output_path):
                    os.remove(output_path)
                return True, "Decrypted version added to repository."
            
            return False, "Failed to unlock PDF: No valid password found."

        except Exception as e: 
            debug_log(f"PDF processing error: {e}")
            return False, str(e)

# Registry for dynamic job lookup
JOB_REGISTRY: Dict[str, Type[BaseJobHandler]] = {
    "UNZIP": UnzipHandler,
    "DECRYPT_PDF": PDFDecryptHandler
}

# --- Workflow Orchestration Logic ---

def get_workflow_rules() -> Dict[str, List[str]]:
    with db.get_connection() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        row = conn.execute("SELECT value FROM settings WHERE key = 'workflow_rules'").fetchone()
        if row:
            return json.loads(row[0])
    
    return {
        "PDF": ["DECRYPT_PDF"],
        "ZIP": ["UNZIP"]
    }

# --- FastAPI Server Setup ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure the worker starts automatically
    await start_integrated_worker()
    yield
    # Shutdown: Clean up the worker
    await stop_integrated_worker()

app = FastAPI(title="RepoArch Modular API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/workflow/config")
async def get_config():
    return get_workflow_rules()

@app.post("/api/workflow/config")
async def update_config(config: WorkflowConfig):
    with db.get_connection() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                     ("workflow_rules", json.dumps(config.rules)))
        conn.commit()
    return {"status": "success", "config": config.rules}

@app.get("/api/credentials")
async def list_credentials():
    with db.get_connection() as conn:
        rows = conn.execute("SELECT id, encrypted_blob, description, created_at FROM credentials").fetchall()
        # Return decrypted values for management UI
        return [{
            "id": r["id"],
            "value": security.decrypt_data(r["encrypted_blob"]),
            "description": r["description"],
            "created_at": r["created_at"]
        } for r in rows]

@app.post("/api/credentials")
async def add_credential(request: Request):
    """
    Handles addition of credentials via JSON POST.
    Expecting: {"value": "password", "description": "optional note"}
    Updated to handle potential 422 errors by inspecting raw body and checking
    for both 'value' and 'password' keys.
    """
    try:
        body = await request.json()
        print(f"\n[SERVER] Received Request Body: {body}", flush=True)
        
        # Check for 'value' or 'password' to accommodate different frontend versions
        val = body.get("value") or body.get("password")
        desc = body.get("description", "")
        
        if not val:
            print("[SERVER] Error: Missing 'value' or 'password' field in request body", flush=True)
            raise HTTPException(status_code=400, detail="Missing credential value")

        print(f"[SERVER] Processing credential: {val}", flush=True)
        sys.stdout.flush()
        
        encrypted = security.encrypt_data(val)
        with db.get_connection() as conn:
            conn.execute(
                "INSERT INTO credentials (encrypted_blob, description, created_at) VALUES (?, ?, ?)",
                (encrypted, desc, datetime.now().isoformat())
            )
            conn.commit()
        return {"status": "success"}
    except HTTPException:
        raise
    except json.JSONDecodeError:
        print("[SERVER] Error: Invalid JSON in request body", flush=True)
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except Exception as e:
        debug_log(f"Error adding credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/credentials/{cred_id}")
async def delete_credential(cred_id: int):
    with db.get_connection() as conn:
        conn.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        conn.commit()
    return {"status": "success"}

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
    stats = dict(res)
    stats["worker_active"] = worker_active
    return stats

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

@app.get("/api/jobs")
async def get_jobs():
    with db.get_connection() as conn:
        rows = conn.execute("""
            SELECT id, job_type, status, attempts, last_error
            FROM jobs 
            ORDER BY id DESC
        """).fetchall()
        return [dict(row) for row in rows]

@app.post("/api/jobs/{job_id}/retry")
async def retry_job(job_id: int):
    with db.get_connection() as conn:
        cursor = conn.cursor()
        job = cursor.execute("SELECT id FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        cursor.execute("""
            UPDATE jobs 
            SET status = 'PENDING', attempts = 0, last_error = NULL, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        """, (job_id,))
        conn.commit()
    return {"status": "success"}

@app.post("/api/worker/start")
async def start_integrated_worker():
    global worker_thread, worker_active
    if worker_active and worker_thread and worker_thread.is_alive():
        return {"status": "already running"}
    
    worker_active = True
    worker_thread = threading.Thread(target=run_worker, name="WorkflowWorker", daemon=True)
    worker_thread.start()
    debug_log("Background worker thread started.")
    return {"status": "started"}

@app.post("/api/worker/stop")
async def stop_integrated_worker():
    global worker_active
    worker_active = False
    return {"status": "stopped"}

# --- Worker Loop ---

def run_worker():
    global worker_active
    debug_log("Worker loop entered.")
    while worker_active:
        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                job = cursor.execute("""
                    SELECT j.*, f.repo 
                    FROM jobs j
                    JOIN files f ON j.file_id = f.id
                    WHERE j.status = 'PENDING' 
                    ORDER BY j.id ASC LIMIT 1
                """).fetchone()
                
                if not job:
                    time.sleep(2)
                    continue
                
                job_id = job['id']
                job_type = job['job_type']
                debug_log(f"Worker picked up job {job_id} ({job_type})")
                
                cursor.execute("UPDATE jobs SET status = 'PROCESSING', updated_at = CURRENT_TIMESTAMP WHERE id = ?", (job_id,))
                conn.commit()

                handler = JOB_REGISTRY.get(job_type)
                if handler:
                    try:
                        success, msg = handler.process(dict(job))
                    except Exception as handler_exc:
                        success, msg = False, f"Handler Exception: {str(handler_exc)}"
                else:
                    success, msg = False, f"No handler registered for type: {job_type}"
                
                new_status = 'COMPLETED' if success else ('FAILED' if job['attempts'] >= 5 else 'PENDING')
                cursor.execute("""
                    UPDATE jobs 
                    SET status = ?, attempts = attempts + 1, last_error = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE id = ?
                """, (new_status, msg, job_id))
                conn.commit()
                debug_log(f"Job {job_id} finished with status: {new_status}")
                
        except Exception as e:
            debug_log(f"Worker loop error: {str(e)}")
            time.sleep(5)

# --- CLI & Logic Orchestration ---
### 3. Summary of Status Meanings
""" * **READY**: The file is usable. (e.g., The PDF is openable or the ZIP is extracted).
* **PENDING**: Waiting in the queue.
* **PROCESSING**: A worker is currently reading/writing this file.
* **LOCKED**: Processing stopped because a password is required. The user needs to add a credential and hit "Retry".
* **FAILED**: A technical error occurred (e.g., Disk full, Corrupt file).
 """
def add_file(repo: str, path: str):
    """
    Core logic to add a file to the repository.
    Calculates unique ID, moves to storage, and triggers workflow jobs.
    """
    debug_log(f"Processing: {path}")
    if not os.path.exists(path): return

    fid = FileManager.calculate_id(path)
    ftype = FileManager.get_type(path)
    filename = os.path.basename(path)
    
    target_dir = os.path.join(REPO_ROOT, repo, fid)
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, filename)
    
    # Only copy if it's not already in its target storage location
    if os.path.abspath(path) != os.path.abspath(target_path):
        shutil.copy2(path, target_path)
    
    workflow_rules = get_workflow_rules()
    jobs_to_trigger = workflow_rules.get(ftype, [])
    # Set initial status
    initial_status = 'PENDING' if jobs_to_trigger else 'READY'      
    
    with db.get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO files (id, name, repo, repo_path, tags, processing_status, file_type) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (fid, filename, repo, target_path, "[]", initial_status, ftype))
        

        for job_type in jobs_to_trigger:
            conn.execute("INSERT INTO jobs (job_type, target_file, file_id) VALUES (?, ?, ?)",
                         (job_type, target_path, fid))
        conn.commit()

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

def main():
    global DEBUG_MODE
    parser = argparse.ArgumentParser(description="RepoArch Unified CLI")
    parser.add_argument("--debug", action="store_true")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("server")
    sub.add_parser("worker")
    
    add_p = sub.add_parser("add")
    add_p.add_argument("repo")
    add_p.add_argument("path")
    
    init_p = sub.add_parser("init")
    init_p.add_argument("name")

    cred_p = sub.add_parser("add-cred")
    cred_p.add_argument("value", help="The credential/password to store")
    cred_p.add_argument("--desc", help="Optional description for the credential")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return
    
    if args.debug: DEBUG_MODE = True
    db.init_db()
    run_security_prompt()

    if args.cmd == "server":
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8000)
    elif args.cmd == "worker":
        global worker_active
        worker_active = True
        run_worker()
    elif args.cmd == "add":
        add_file(args.repo, args.path)
    elif args.cmd == "init":
        os.makedirs(os.path.join(REPO_ROOT, args.name), exist_ok=True)
    elif args.cmd == "add-cred":
        encrypted = security.encrypt_data(args.value)
        with db.get_connection() as conn:
            conn.execute(
                "INSERT INTO credentials (encrypted_blob, description, created_at) VALUES (?, ?, ?)",
                (encrypted, args.desc, datetime.now().isoformat())
            )
            conn.commit()
        print("Credential added and encrypted.", flush=True)

if __name__ == "__main__":
    main()