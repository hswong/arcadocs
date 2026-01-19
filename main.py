import argparse
import sqlite3
import os
import hashlib
import shutil
import stat
import base64
import getpass
from datetime import datetime

class RepoManager:
    """
    Manages an archival repository using a SQLite database with encrypted credentials.
    The master REPO_KEY is protected by a user-defined unlock password.
    Credentials are stored in a pool to be tried against protected files.
    """
    
    def __init__(self):
        """Initializes the RepoManager."""
        self.repo_root = os.environ.get('REPO_ROOT')
        if not self.repo_root:
            raise EnvironmentError("REPO_ROOT environment variable is not set.")
        
        self.config_path = os.path.join(self.repo_root, '.repo_config')
        self.db_path = os.path.join(self.repo_root, 'repo.db')
        self.repo_key = self._initialize_master_key()
        self.conn = None
        
        # Auto-ensure schema on every instantiation to prevent "no such table" errors
        self._ensure_schema()

    def _initialize_master_key(self):
        """Retrieves or creates the master encryption key."""
        env_key = os.environ.get('REPO_KEY')
        if env_key:
            return env_key

        if os.path.exists(self.config_path):
            password = getpass.getpass("Enter Master Password to unlock REPO_KEY: ")
            with open(self.config_path, "r") as f:
                encrypted_master_key = f.read().strip()
            
            decrypted = self._simple_decrypt_with_pass(encrypted_master_key, password)
            if decrypted.startswith("VALID:"):
                return decrypted[6:]
            else:
                print("Error: Invalid Master Password.")
                exit(1)
        
        print("No REPO_KEY found. Initializing security configuration...")
        new_key = getpass.getpass("Create a new REPO_KEY (Secret for file credentials): ")
        new_pass = getpass.getpass("Create a Master Password to protect this REPO_KEY: ")
        
        encrypted_to_store = self._simple_encrypt_with_pass(f"VALID:{new_key}", new_pass)
        
        with open(self.config_path, "w") as f:
            f.write(encrypted_to_store)
        
        os.chmod(self.config_path, stat.S_IRUSR | stat.S_IWUSR)
        print(f"Master configuration saved to {self.config_path}")
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
        except Exception:
            return ""

    def _cipher_logic(self, data, key):
        extended_key = (key * (len(data) // len(key) + 1))[:len(data)]
        return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(data, extended_key))

    def _cipher(self, data):
        return self._cipher_logic(data, self.repo_key)

    def _encrypt(self, plain_text):
        ciphered = self._cipher(plain_text)
        return base64.b64encode(ciphered.encode()).decode()

    def _decrypt(self, cipher_text):
        try:
            decoded = base64.b64decode(cipher_text.encode()).decode()
            return self._cipher(decoded)
        except Exception:
            return "[Decryption Error: Key Mismatch]"

    def _connect_db(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA foreign_keys = ON;")
        
    def _close_db(self):
        if self.conn:
            self.conn.close()

    def _ensure_schema(self):
        """Creates the database schema if it does not already exist."""
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tags (
                    tag_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tag_name TEXT NOT NULL UNIQUE
                )
            ''')
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
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_tags (
                    file_id TEXT NOT NULL,
                    tag_id INTEGER NOT NULL,
                    PRIMARY KEY (file_id, tag_id),
                    FOREIGN KEY (file_id) REFERENCES files(file_id) ON DELETE CASCADE,
                    FOREIGN KEY (tag_id) REFERENCES tags(tag_id) ON DELETE CASCADE
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    cred_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    credential_value TEXT NOT NULL UNIQUE,
                    description TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            self.conn.commit()
        finally:
            self._close_db()

    def _calculate_file_id(self, file_path):
        file_size = os.path.getsize(file_path)
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return f"{file_size}_{sha256_hash.hexdigest()}"

    def init(self, repo_name):
        """Initializes the directory for a new repository."""
        repo_path = os.path.join(self.repo_root, repo_name)
        if not os.path.exists(repo_path):
            os.makedirs(repo_path)
            print(f"Repository directory '{repo_name}' created.")
        else:
            print(f"Repository directory '{repo_name}' already exists.")

    def add_credential(self, password, description=None):
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            encrypted_val = self._encrypt(password)
            cursor.execute('''
                INSERT OR IGNORE INTO credentials (credential_value, description)
                VALUES (?, ?)
            ''', (encrypted_val, description))
            self.conn.commit()
            print("Credential managed.")
        finally:
            self._close_db()

    def list_credentials(self):
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute("SELECT cred_id, credential_value, description FROM credentials")
            rows = cursor.fetchall()
            for row in rows:
                print(f"ID: {row[0]} | Cred: {self._decrypt(row[1])} | Desc: {row[2]}")
        finally:
            self._close_db()

    def del_credential(self, cred_id):
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM credentials WHERE cred_id = ?", (cred_id,))
            self.conn.commit()
        finally:
            self._close_db()

    def _add_to_repo(self, repo_name, source_path, original_path):
        """
        Internal function to add a file to the repository.
        Preserves original filename by placing it inside a unique file_id directory.
        Prints duplicate paths if the hash already exists.
        """
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            repo_path_root = os.path.join(self.repo_root, repo_name)
            if not os.path.exists(repo_path_root):
                print(f"Error: Repo '{repo_name}' not initialized. Run init first.")
                return False

            file_id = self._calculate_file_id(source_path)
            
            # Check for duplicates by hash
            cursor.execute("SELECT original_path, repo_name FROM files WHERE file_id = ?", (file_id,))
            existing = cursor.fetchone()
            if existing:
                print(f"Duplicate detected (Hash: {file_id})")
                print(f"  Existing file: {existing[0]} (in repo: {existing[1]})")
                print(f"  Skipping new: {source_path}")
                return False

            # Get the original filename from the source path
            original_filename = os.path.basename(source_path)
            
            # Create a directory named after the file_id to store the file
            file_storage_dir = os.path.join(repo_path_root, file_id)
            if not os.path.exists(file_storage_dir):
                os.makedirs(file_storage_dir)
            
            repo_file_path = os.path.join(file_storage_dir, original_filename)
            shutil.copy2(source_path, repo_file_path)

            # Store the relative path within the repo
            db_repo_path = os.path.join(repo_name, file_id, original_filename)

            cursor.execute('''
                INSERT INTO files (file_id, repo_name, original_path, repo_path)
                VALUES (?, ?, ?, ?)
            ''', (file_id, repo_name, original_path, db_repo_path))
            
            self.conn.commit()
            print(f"File added: {file_id} (Stored as: {original_filename})")
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False
        finally:
            self._close_db()

    def check_folder(self, folder_path):
        """
        Scans a folder for 0-byte files and files already existing in the repository.
        """
        if not os.path.isdir(folder_path):
            print(f"Error: {folder_path} is not a directory.")
            return

        print(f"Checking folder: {folder_path}...")
        
        zero_byte_files = []
        duplicate_files = []

        try:
            self._connect_db()
            cursor = self.conn.cursor()

            for root, _, files in os.walk(folder_path):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    
                    # 1. Check for 0-byte files
                    if os.path.getsize(file_path) == 0:
                        zero_byte_files.append(file_path)
                        continue

                    # 2. Check if file already exists in repo
                    file_id = self._calculate_file_id(file_path)
                    cursor.execute("SELECT original_path, repo_name FROM files WHERE file_id = ?", (file_id,))
                    existing = cursor.fetchone()
                    if existing:
                        duplicate_files.append({
                            'new_path': file_path,
                            'existing_path': existing[0],
                            'repo': existing[1],
                            'file_id': file_id
                        })

            print("\n--- Summary ---")
            
            if zero_byte_files:
                print(f"\n[!] Found {len(zero_byte_files)} empty (0-byte) files:")
                for f in zero_byte_files:
                    print(f"  - {f}")
            else:
                print("\n[+] No empty files found.")

            if duplicate_files:
                print(f"\n[!] Found {len(duplicate_files)} duplicate files already in repository:")
                for d in duplicate_files:
                    print(f"  - New:      {d['new_path']}")
                    print(f"    Existing: {d['existing_path']} (Repo: {d['repo']})")
                    print(f"    Hash:     {d['file_id']}")
            else:
                print("\n[+] No duplicates found.")

        except Exception as e:
            print(f"Error during check: {e}")
        finally:
            self._close_db()

    def import_folder(self, repo_name, folder_path):
        if not os.path.isdir(folder_path):
            print(f"Error: {folder_path} is not a directory.")
            return
            
        self._connect_db()
        cursor = self.conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO tags (tag_name) VALUES (?)", (folder_path,))
        self.conn.commit()
        cursor.execute("SELECT tag_id FROM tags WHERE tag_name = ?", (folder_path,))
        tag_id = cursor.fetchone()[0]
        self._close_db()

        for root, _, files in os.walk(folder_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, folder_path)
                if self._add_to_repo(repo_name, file_path, rel_path):
                    fid = self._calculate_file_id(file_path)
                    self._connect_db()
                    self.conn.execute("INSERT OR IGNORE INTO file_tags (file_id, tag_id) VALUES (?, ?)", (fid, tag_id))
                    self.conn.commit()
                    self._close_db()

    def add(self, repo_name, file_path):
        if os.path.isfile(file_path):
            self._add_to_repo(repo_name, file_path, file_path)

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
                
                # Use shutil.rmtree on the storage_dir to remove the ID folder and its content
                if os.path.exists(storage_dir) and os.path.isdir(storage_dir):
                    shutil.rmtree(storage_dir)
                elif os.path.exists(full_path):
                    os.remove(full_path)
                    
                cursor.execute("DELETE FROM files WHERE file_id = ?", (file_id,))
                self.conn.commit()
                print(f"Removed {file_id}")
        finally:
            self._close_db()

    def del_tag(self, repo_name, file_id, tag_name):
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM file_tags WHERE file_id = ? AND tag_id IN (SELECT tag_id FROM tags WHERE tag_name = ?)", (file_id, tag_name))
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
            if not os.path.exists(target_storage_dir):
                os.makedirs(target_storage_dir)
            
            new_repo_path = os.path.join(target_repo, file_id, filename)
            new_full_path = os.path.join(self.repo_root, new_repo_path)
            
            # If the source path is actually a file, move it. If it's the dir, handle accordingly.
            if os.path.isfile(old_full_path):
                shutil.move(old_full_path, new_full_path)
            
            old_storage_dir = os.path.dirname(old_full_path)
            if os.path.exists(old_storage_dir) and os.path.isdir(old_storage_dir) and not os.listdir(old_storage_dir):
                os.rmdir(old_storage_dir)

            cursor.execute("UPDATE files SET status = 'MOVED' WHERE file_id = ? AND repo_name = ?", (file_id, source_repo))
            cursor.execute("INSERT INTO files (file_id, repo_name, original_path, repo_path) VALUES (?, ?, ?, ?)", 
                           (file_id, target_repo, source[1], new_repo_path))
            self.conn.commit()
            print(f"Moved {file_id} to {target_repo}")
        finally:
            self._close_db()

def main():
    parser = argparse.ArgumentParser(description="Archival Repository Manager")
    subparsers = parser.add_subparsers(dest='command')
    subparsers.add_parser('init').add_argument('repo_name')
    # Fixed: check command only takes folder_path, not repo_name
    chk = subparsers.add_parser('check'); chk.add_argument('repo_name'); chk.add_argument('folder_path')
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
    try:
        manager = RepoManager()
        if args.command == 'init': manager.init(args.repo_name)
        elif args.command == 'check': manager.check_folder(args.folder_path)
        elif args.command == 'import': manager.import_folder(args.repo_name, args.folder_path)
        elif args.command == 'add': manager.add(args.repo_name, args.file_path)
        elif args.command == 'tag': manager.tag(args.repo_name, args.file_id, args.tag_name)
        elif args.command == 'remove': manager.remove(args.repo_name, args.file_id)
        elif args.command == 'del-tag': manager.del_tag(args.repo_name, args.file_id, args.tag_name)
        elif args.command == 'move': manager.move(args.source_repo, args.file_id, args.target_repo)
        elif args.command == 'add-cred': manager.add_credential(args.password, args.desc)
        elif args.command == 'list-creds': manager.list_credentials()
        elif args.command == 'del-cred': manager.del_credential(args.cred_id)
    except Exception as e:
        print(f"Operational Error: {e}")

if __name__ == "__main__":
    main()