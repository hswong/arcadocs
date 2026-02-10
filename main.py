import argparse
import sqlite3
import os
import hashlib
import shutil
import stat
import base64
import getpass
import zipfile
import threading
import time
from datetime import datetime

# Optional: For PDF password removal. 
# Install with: pip install pikepdf
try:
    import pikepdf
    HAS_PIKE = True
except ImportError:
    HAS_PIKE = False

class RepoManager:
    """
    Manages an archival repository with background processing for 
    compressed files and password-protected PDFs.
    """
    
    def __init__(self):
        self.repo_root = os.environ.get('REPO_ROOT')
        if not self.repo_root:
            raise EnvironmentError("REPO_ROOT environment variable is not set.")
        
        self.config_path = os.path.join(self.repo_root, '.repo_config')
        self.db_path = os.path.join(self.repo_root, 'repo.db')
        self.repo_key = self._initialize_master_key()
        self.conn = None
        
        self._ensure_schema()

    def _initialize_master_key(self):
        env_key = os.environ.get('REPO_KEY')
        if env_key: return env_key
        if os.path.exists(self.config_path):
            password = getpass.getpass("Enter Master Password to unlock REPO_KEY: ")
            with open(self.config_path, "r") as f:
                encrypted_master_key = f.read().strip()
            decrypted = self._simple_decrypt_with_pass(encrypted_master_key, password)
            if decrypted.startswith("VALID:"): return decrypted[6:]
            else: print("Error: Invalid Master Password."); exit(1)
        print("No REPO_KEY found. Initializing security configuration...")
        new_key = getpass.getpass("Create a new REPO_KEY: ")
        new_pass = getpass.getpass("Create a Master Password: ")
        encrypted_to_store = self._simple_encrypt_with_pass(f"VALID:{new_key}", new_pass)
        with open(self.config_path, "w") as f: f.write(encrypted_to_store)
        os.chmod(self.config_path, stat.S_IRUSR | stat.S_IWUSR)
        return new_key

    def _simple_encrypt_with_pass(self, plain_text, password):
        key = hashlib.sha256(password.encode()).hexdigest()
        ciphered = self._cipher_logic(plain_text, key)
        return base64.b64encode(ciphered.encode()).decode()

    def _simple_decrypt_with_pass(self, cipher_text, password):
        try:
            key = hashlib.sha256(password.encode()).hexdigest()
            decoded = base64.b64decode(cipher_text.encode()).decode()
            return self._cipher_logic(decoded, key)
        except Exception: return ""

    def _cipher_logic(self, data, key):
        extended_key = (key * (len(data) // len(key) + 1))[:len(data)]
        return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(data, extended_key))

    def _cipher(self, data): return self._cipher_logic(data, self.repo_key)
    def _encrypt(self, plain_text): return base64.b64encode(self._cipher(plain_text).encode()).decode()
    def _decrypt(self, cipher_text):
        try: return self._cipher(base64.b64decode(cipher_text.encode()).decode())
        except Exception: return "[Decryption Error]"

    def _connect_db(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA foreign_keys = ON;")
        
    def _close_db(self):
        if self.conn: self.conn.close()

    def _ensure_schema(self):
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute('CREATE TABLE IF NOT EXISTS tags (tag_id INTEGER PRIMARY KEY AUTOINCREMENT, tag_name TEXT NOT NULL UNIQUE)')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    file_id TEXT PRIMARY KEY,
                    repo_name TEXT NOT NULL,
                    original_path TEXT NOT NULL,
                    repo_path TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'ACTIVE',
                    UNIQUE(repo_name, repo_path)
                )
            ''')
            cursor.execute('CREATE TABLE IF NOT EXISTS file_tags (file_id TEXT NOT NULL, tag_id INTEGER NOT NULL, PRIMARY KEY (file_id, tag_id), FOREIGN KEY (file_id) REFERENCES files(file_id) ON DELETE CASCADE, FOREIGN KEY (tag_id) REFERENCES tags(tag_id) ON DELETE CASCADE)')
            cursor.execute('CREATE TABLE IF NOT EXISTS credentials (cred_id INTEGER PRIMARY KEY AUTOINCREMENT, credential_value TEXT NOT NULL UNIQUE, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id TEXT NOT NULL,
                    job_type TEXT NOT NULL,
                    status TEXT DEFAULT 'PENDING',
                    attempts INTEGER DEFAULT 0,
                    last_error TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (file_id) REFERENCES files(file_id) ON DELETE CASCADE
                )
            ''')
            self.conn.commit()
        finally:
            self._close_db()

    def _calculate_file_id(self, file_path):
        file_size = os.path.getsize(file_path)
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""): sha256_hash.update(byte_block)
        return f"{file_size}_{sha256_hash.hexdigest()}"

    def _get_file_type_by_magic(self, file_path):
        """Identifies file type using magic numbers (file signatures) and content inspection."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(2048)
                # Binary Signatures
                if header.startswith(b'PK\x03\x04'):
                    if b'xl/' in header: return 'XLSX'
                    return 'ZIP'
                if header.startswith(b'%PDF'):
                    return 'PDF'
                if header.startswith(b'Rar!'):
                    return 'RAR'
                if header.startswith(b'7z\xbc\xaf\x27\x1c'):
                    return '7Z'
                
                # Check if it looks like binary (presence of null bytes or non-text control chars)
                # Most text files don't have null bytes \x00
                if b'\x00' in header:
                    return 'UNKNOWN'

                # Text-based detection
                try:
                    content_str = header.decode('utf-8').strip()
                    content_lower = content_str.lower()
                    
                    if content_lower.startswith(('<!doctype html', '<html')):
                        return 'HTML'
                    
                    # More strict CSV detection: check consistency of column count in first few lines
                    if ',' in content_str and '\n' in content_str:
                        lines = [l for l in content_str.split('\n') if l.strip()]
                        if len(lines) > 1:
                            col_counts = [l.count(',') for l in lines[:3]]
                            if all(c > 0 for c in col_counts) and len(set(col_counts)) == 1:
                                return 'CSV'
                    
                    return 'TEXT'
                except UnicodeDecodeError:
                    pass
        except Exception:
            pass
        return 'UNKNOWN'

    def _queue_job(self, file_id, file_path):
        """Detects if a job is needed based on file magic and adds to queue."""
        file_type = self._get_file_type_by_magic(file_path)
        
        self._connect_db()
        cursor = self.conn.cursor()
        
        # We only queue UNZIP if it is a standard ZIP, not an XLSX
        if file_type == 'ZIP':
            cursor.execute("INSERT INTO jobs (file_id, job_type) VALUES (?, 'UNZIP')", (file_id,))
        elif file_type == 'PDF':
            cursor.execute("INSERT INTO jobs (file_id, job_type) VALUES (?, 'DECRYPT_PDF')", (file_id,))
            
        self.conn.commit()
        self._close_db()

    def init(self, repo_name):
        repo_path = os.path.join(self.repo_root, repo_name)
        if not os.path.exists(repo_path):
            os.makedirs(repo_path)
            print(f"Repository directory '{repo_name}' created.")
        else:
            print(f"Repository directory '{repo_name}' already exists.")

    def add_credential(self, password, description=None):
        try:
            self._connect_db()
            encrypted_val = self._encrypt(password)
            self.conn.execute("INSERT OR IGNORE INTO credentials (credential_value, description) VALUES (?, ?)", (encrypted_val, description))
            self.conn.commit()
            print("Credential managed.")
        finally:
            self._close_db()

    def list_credentials(self):
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute("SELECT cred_id, credential_value, description FROM credentials")
            for row in cursor.fetchall():
                print(f"ID: {row[0]} | Cred: {self._decrypt(row[1])} | Desc: {row[2]}")
        finally:
            self._close_db()

    def del_credential(self, cred_id):
        try:
            self._connect_db()
            self.conn.execute("DELETE FROM credentials WHERE cred_id = ?", (cred_id,))
            self.conn.commit()
        finally:
            self._close_db()

    def _add_to_repo(self, repo_name, source_path, original_path):
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            repo_path_root = os.path.join(self.repo_root, repo_name)
            if not os.path.exists(repo_path_root): return False

            file_id = self._calculate_file_id(source_path)
            
            # Check for existing file record
            cursor.execute("SELECT repo_path, repo_name FROM files WHERE file_id = ?", (file_id,))
            existing = cursor.fetchone()
            if existing:
                print(f"Duplicate detected: {file_id}. Already in repo '{existing[1]}'.")
                return file_id # Return file_id to allow tagging of existing file

            original_filename = os.path.basename(source_path)
            file_storage_dir = os.path.join(repo_path_root, file_id)
            if not os.path.exists(file_storage_dir): os.makedirs(file_storage_dir)
            
            repo_file_path = os.path.join(file_storage_dir, original_filename)
            shutil.copy2(source_path, repo_file_path)

            db_repo_path = os.path.join(repo_name, file_id, original_filename)
            cursor.execute('INSERT INTO files (file_id, repo_name, original_path, repo_path) VALUES (?, ?, ?, ?)', 
                           (file_id, repo_name, original_path, db_repo_path))
            self.conn.commit()
            self._close_db()
            
            self._queue_job(file_id, repo_file_path)
            print(f"File added: {file_id}")
            return file_id
        except Exception as e:
            print(f"Error adding: {e}")
            return None

    def check_folder(self, folder_path):
        if not os.path.isdir(folder_path):
            print(f"Error: {folder_path} is not a directory.")
            return
        print(f"Checking {folder_path}...")
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            for root, _, files in os.walk(folder_path):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    # Get file type using magic bytes
                    file_type = self._get_file_type_by_magic(file_path)
                    
                    if os.path.getsize(file_path) == 0:
                        print(f"[!] Empty file [{file_type}]: {file_path}")
                        continue
                        
                    fid = self._calculate_file_id(file_path)
                    cursor.execute("SELECT original_path, repo_name FROM files WHERE file_id = ?", (fid,))
                    existing = cursor.fetchone()
                    
                    status_msg = f"OK [{file_type}]"
                    if existing:
                        status_msg = f"DUPLICATE [{file_type}] (In repo: {existing[1]})"
                    
                    print(f"{status_msg}: {file_path}")
        finally:
            self._close_db()

    def import_folder(self, repo_name, folder_path):
        if not os.path.isdir(folder_path):
            print(f"Error: '{folder_path}' is not a valid directory. Import aborted.")
            return
            
        self._connect_db()
        self.conn.execute("INSERT OR IGNORE INTO tags (tag_name) VALUES (?)", (folder_path,))
        self.conn.commit()
        cursor = self.conn.cursor()
        cursor.execute("SELECT tag_id FROM tags WHERE tag_name = ?", (folder_path,))
        tag_id = cursor.fetchone()[0]
        self._close_db()

        for root, _, files in os.walk(folder_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, folder_path)
                fid = self._add_to_repo(repo_name, file_path, rel_path)
                if fid:
                    self._connect_db()
                    self.conn.execute("INSERT OR IGNORE INTO file_tags (file_id, tag_id) VALUES (?, ?)", (fid, tag_id))
                    self.conn.commit()
                    self._close_db()

    def add(self, repo_name, file_path):
        if os.path.isfile(file_path):
            self._add_to_repo(repo_name, file_path, file_path)
        else:
            print(f"Error: '{file_path}' is not a valid file.")

    def tag(self, repo_name, file_id, tag_name):
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO tags (tag_name) VALUES (?)", (tag_name,))
            cursor.execute("SELECT tag_id FROM tags WHERE tag_name = ?", (tag_name,))
            tid = cursor.fetchone()[0]
            cursor.execute("INSERT OR IGNORE INTO file_tags (file_id, tag_id) VALUES (?, ?)", (file_id, tid))
            self.conn.commit()
        finally:
            self._close_db()

    def remove(self, repo_name, file_id):
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute("SELECT repo_path FROM files WHERE file_id = ?", (file_id,))
            res = cursor.fetchone()
            if res:
                full_path = os.path.join(self.repo_root, res[0])
                storage_dir = os.path.dirname(full_path)
                if os.path.exists(storage_dir): shutil.rmtree(storage_dir)
                cursor.execute("DELETE FROM files WHERE file_id = ?", (file_id,))
                self.conn.commit()
                print(f"Removed {file_id}")
        finally:
            self._close_db()

    def del_tag(self, repo_name, file_id, tag_name):
        try:
            self._connect_db()
            self.conn.execute("DELETE FROM file_tags WHERE file_id = ? AND tag_id IN (SELECT tag_id FROM tags WHERE tag_name = ?)", (file_id, tag_name))
            self.conn.commit()
        finally:
            self._close_db()

    def move(self, source_repo, file_id, target_repo):
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute("SELECT repo_path, original_path FROM files WHERE file_id = ? AND repo_name = ?", (file_id, source_repo))
            source = cursor.fetchone()
            if not source: return
            
            old_full_path = os.path.join(self.repo_root, source[0])
            filename = os.path.basename(old_full_path)
            target_storage_dir = os.path.join(self.repo_root, target_repo, file_id)
            if not os.path.exists(target_storage_dir): os.makedirs(target_storage_dir)
            
            new_repo_path = os.path.join(target_repo, file_id, filename)
            shutil.move(old_full_path, os.path.join(self.repo_root, new_repo_path))
            
            old_storage_dir = os.path.dirname(old_full_path)
            if not os.listdir(old_storage_dir): os.rmdir(old_storage_dir)

            cursor.execute("UPDATE files SET status = 'MOVED' WHERE file_id = ? AND repo_name = ?", (file_id, source_repo))
            cursor.execute("INSERT INTO files (file_id, repo_name, original_path, repo_path) VALUES (?, ?, ?, ?)", 
                           (file_id, target_repo, source[1], new_repo_path))
            self.conn.commit()
            print(f"Moved {file_id} to {target_repo}")
        finally:
            self._close_db()

    def process_jobs(self):
        """Worker loop to process pending jobs."""
        print("Starting job processor... (Ctrl+C to stop)")
        while True:
            try:
                self._connect_db()
                cursor = self.conn.cursor()
                cursor.execute("SELECT job_id, file_id, job_type, attempts FROM jobs WHERE status = 'PENDING' LIMIT 1")
                job = cursor.fetchone()
                self._close_db()

                if not job:
                    time.sleep(5)
                    continue

                job_id, file_id, job_type, attempts = job
                success, error_msg = False, ""

                self._connect_db()
                cursor = self.conn.cursor()
                cursor.execute("SELECT repo_path, repo_name FROM files WHERE file_id = ?", (file_id,))
                file_info = cursor.fetchone()
                self._close_db()

                if file_info:
                    full_path = os.path.join(self.repo_root, file_info[0])
                    repo_name = file_info[1]
                    if job_type == 'UNZIP': success, error_msg = self._handle_unzip(repo_name, full_path)
                    elif job_type == 'DECRYPT_PDF': success, error_msg = self._handle_pdf_decrypt(full_path)

                self._connect_db()
                if success:
                    self.conn.execute("UPDATE jobs SET status = 'COMPLETED', updated_at = CURRENT_TIMESTAMP WHERE job_id = ?", (job_id,))
                else:
                    status = 'FAILED' if attempts >= 5 else 'PENDING'
                    self.conn.execute("UPDATE jobs SET status = ?, attempts = attempts + 1, last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE job_id = ?", 
                                   (status, error_msg, job_id))
                self.conn.commit()
                self._close_db()
            except KeyboardInterrupt: break
            except Exception as e:
                print(f"Worker Error: {e}")
                time.sleep(5)

    def _handle_unzip(self, repo_name, zip_path):
        try:
            extract_to = zip_path + "_extracted"
            with zipfile.ZipFile(zip_path, 'r') as zip_ref: zip_ref.extractall(extract_to)
            for root, _, files in os.walk(extract_to):
                for f in files:
                    child_path = os.path.join(root, f)
                    self._add_to_repo(repo_name, child_path, f"EXTRACTED/{os.path.relpath(child_path, extract_to)}")
            shutil.rmtree(extract_to)
            return True, ""
        except Exception as e: return False, str(e)

    def _handle_pdf_decrypt(self, pdf_path):
        if not HAS_PIKE: return False, "pikepdf not installed"
        try:
            try:
                with pikepdf.open(pdf_path) as pdf: return True, "Already decrypted"
            except pikepdf.PasswordError: pass

            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute("SELECT credential_value FROM credentials")
            creds = [self._decrypt(r[0]) for r in cursor.fetchall()]
            self._close_db()

            for password in creds:
                try:
                    with pikepdf.open(pdf_path, password=password) as pdf:
                        temp_path = pdf_path + ".unlocked"
                        pdf.save(temp_path)
                        os.replace(temp_path, pdf_path)
                        return True, ""
                except pikepdf.PasswordError: continue
            return False, "No valid password found"
        except Exception as e: return False, str(e)

def main():
    parser = argparse.ArgumentParser(description="Archival Repository Manager")
    subparsers = parser.add_subparsers(dest='command')
    subparsers.add_parser('init').add_argument('repo_name')
    subparsers.add_parser('check').add_argument('folder_path')
    subparsers.add_parser('worker')
    imp = subparsers.add_parser('import'); imp.add_argument('repo_name'); imp.add_argument('folder_path')
    ad = subparsers.add_parser('add'); ad.add_argument('repo_name'); ad.add_argument('file_path')
    tg = subparsers.add_parser('tag'); tg.add_argument('repo_name'); tg.add_argument('file_id'); tg.add_argument('tag_name')
    rm = subparsers.add_parser('remove'); rm.add_argument('repo_name'); rm.add_argument('file_id')
    dt = subparsers.add_parser('del-tag'); dt.add_argument('repo_name'); dt.add_argument('file_id'); dt.add_argument('tag_name')
    mv = subparsers.add_parser('move'); mv.add_argument('source_repo'); mv.add_argument('file_id'); mv.add_argument('target_repo')
    cs = subparsers.add_parser('add-cred'); cs.add_argument('password'); cs.add_argument('--desc')
    subparsers.add_parser('list-creds')
    cd = subparsers.add_parser('del-cred'); cd.add_argument('cred_id', type=int)

    args = parser.parse_args()
    manager = RepoManager()
    if args.command == 'init': manager.init(args.repo_name)
    elif args.command == 'check': manager.check_folder(args.folder_path)
    elif args.command == 'worker': manager.process_jobs()
    elif args.command == 'import': manager.import_folder(args.repo_name, args.folder_path)
    elif args.command == 'add': manager.add(args.repo_name, args.file_path)
    elif args.command == 'tag': manager.tag(args.repo_name, args.file_id, args.tag_name)
    elif args.command == 'remove': manager.remove(args.repo_name, args.file_id)
    elif args.command == 'del-tag': manager.del_tag(args.repo_name, args.file_id, args.tag_name)
    elif args.command == 'move': manager.move(args.source_repo, args.file_id, args.target_repo)
    elif args.command == 'add-cred': manager.add_credential(args.password, args.desc)
    elif args.command == 'list-creds': manager.list_credentials()
    elif args.command == 'del-cred': manager.del_credential(args.cred_id)

if __name__ == "__main__":
    main()