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

    def _initialize_master_key(self):
        """
        Retrieves the REPO_KEY from environment, or decrypts it from config using a password,
        or prompts the user to create one if it doesn't exist.
        """
        # 1. Check environment variable first (legacy support/automation)
        env_key = os.environ.get('REPO_KEY')
        if env_key:
            return env_key

        # 2. Check if we have an encrypted key stored in the config file
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
        
        # 3. No key found anywhere, prompt user to create one
        print("No REPO_KEY found. Initializing security configuration...")
        new_key = getpass.getpass("Create a new REPO_KEY (Secret for file credentials): ")
        new_pass = getpass.getpass("Create a Master Password to protect this REPO_KEY: ")
        
        # Store the key encrypted by the password
        # Prefix with "VALID:" to verify correct decryption later
        encrypted_to_store = self._simple_encrypt_with_pass(f"VALID:{new_key}", new_pass)
        
        with open(self.config_path, "w") as f:
            f.write(encrypted_to_store)
        
        os.chmod(self.config_path, stat.S_IRUSR | stat.S_IWUSR) # Restricted permissions
        print(f"Master configuration saved to {self.config_path}")
        return new_key

    def _simple_encrypt_with_pass(self, plain_text, password):
        """Derives a key from the password to encrypt text."""
        key = hashlib.sha256(password.encode()).hexdigest()
        ciphered = self._cipher_logic(plain_text, key)
        return base64.b64encode(ciphered.encode()).decode()

    def _simple_decrypt_with_pass(self, cipher_text, password):
        """Derives a key from the password to decrypt text."""
        try:
            key = hashlib.sha256(password.encode()).hexdigest()
            decoded = base64.b64decode(cipher_text.encode()).decode()
            return self._cipher_logic(decoded, key)
        except Exception:
            return ""

    def _cipher_logic(self, data, key):
        """Generic XOR cipher logic."""
        extended_key = (key * (len(data) // len(key) + 1))[:len(data)]
        return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(data, extended_key))

    def _cipher(self, data):
        """Encryption logic using the unlocked REPO_KEY."""
        return self._cipher_logic(data, self.repo_key)

    def _encrypt(self, plain_text):
        """Encrypts plain text to a base64 encoded XOR string."""
        ciphered = self._cipher(plain_text)
        return base64.b64encode(ciphered.encode()).decode()

    def _decrypt(self, cipher_text):
        """Decrypts a base64 encoded XOR string back to plain text."""
        try:
            decoded = base64.b64decode(cipher_text.encode()).decode()
            return self._cipher(decoded)
        except Exception:
            return "[Decryption Error: Key Mismatch]"

    def _connect_db(self):
        """Establishes a connection to the SQLite database."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA foreign_keys = ON;")
        
    def _close_db(self):
        """Closes the database connection."""
        if self.conn:
            self.conn.close()

    def _calculate_file_id(self, file_path):
        """Calculates a unique file ID based on file size and SHA256 hash."""
        file_size = os.path.getsize(file_path)
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return f"{file_size}_{sha256_hash.hexdigest()}"

    def init(self, repo_name):
        """Initializes a new repository within REPO_ROOT."""
        try:
            repo_path = os.path.join(self.repo_root, repo_name)
            if not os.path.exists(repo_path):
                os.makedirs(repo_path)
            
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

            # Updated table: Credentials are now a pool (id based) rather than 1-1 with files
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    cred_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    credential_value TEXT NOT NULL UNIQUE,
                    description TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            self.conn.commit()
            print(f"Repository '{repo_name}' initialized successfully with Credential Pool.")

        except sqlite3.Error as e:
            print(f"Database error: {e}")
        finally:
            self._close_db()

    def add_credential(self, password, description=None):
        """Encrypts and adds a password to the global credential pool."""
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            encrypted_val = self._encrypt(password)
            
            cursor.execute('''
                INSERT OR IGNORE INTO credentials (credential_value, description)
                VALUES (?, ?)
            ''', (encrypted_val, description))
            
            self.conn.commit()
            if cursor.rowcount > 0:
                print("Credential added to the pool.")
            else:
                print("This credential already exists in the pool.")
        finally:
            self._close_db()

    def list_credentials(self):
        """Lists all decrypted credentials currently in the pool."""
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute("SELECT cred_id, credential_value, description FROM credentials")
            rows = cursor.fetchall()
            if rows:
                print(f"{'ID':<5} | {'Credential':<20} | {'Description'}")
                print("-" * 50)
                for row in rows:
                    decrypted = self._decrypt(row[1])
                    desc = row[2] if row[2] else ""
                    print(f"{row[0]:<5} | {decrypted:<20} | {desc}")
            else:
                print("Credential pool is empty.")
        finally:
            self._close_db()

    def del_credential(self, cred_id):
        """Removes a credential from the pool by its ID."""
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM credentials WHERE cred_id = ?", (cred_id,))
            self.conn.commit()
            if cursor.rowcount > 0:
                print(f"Credential {cred_id} removed from pool.")
            else:
                print(f"Credential ID {cred_id} not found.")
        finally:
            self._close_db()

    def get_credential_pool(self):
        """Returns the list of all decrypted credentials for trial-and-error decryption."""
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute("SELECT credential_value FROM credentials")
            return [self._decrypt(row[0]) for row in cursor.fetchall()]
        finally:
            self._close_db()

    def _add_to_repo(self, repo_name, source_path, original_path):
        """Internal function to add a file to the repository."""
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            repo_path_root = os.path.join(self.repo_root, repo_name)
            if not os.path.exists(repo_path_root):
                print(f"Error: Repo '{repo_name}' not found.")
                return False

            file_id = self._calculate_file_id(source_path)
            cursor.execute("SELECT repo_name FROM files WHERE file_id = ?", (file_id,))
            if cursor.fetchone():
                print(f"Warning: File {file_id} already exists.")
                return False

            repo_file_path = os.path.join(repo_path_root, file_id)
            shutil.copy2(source_path, repo_file_path)

            cursor.execute('''
                INSERT INTO files (file_id, repo_name, original_path, repo_path)
                VALUES (?, ?, ?, ?)
            ''', (file_id, repo_name, original_path, os.path.join(repo_name, file_id)))
            
            self.conn.commit()
            print(f"File added: {file_id}")
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False
        finally:
            self._close_db()

    def add(self, repo_name, file_path):
        if os.path.isfile(file_path):
            self._add_to_repo(repo_name, file_path, file_path)

    def import_folder(self, repo_name, folder_path):
        if not os.path.isdir(folder_path): return
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
                if self._add_to_repo(repo_name, file_path, os.path.relpath(file_path, folder_path)):
                    fid = self._calculate_file_id(file_path)
                    self._connect_db()
                    self.conn.execute("INSERT OR IGNORE INTO file_tags (file_id, tag_id) VALUES (?, ?)", (fid, tag_id))
                    self.conn.commit()
                    self._close_db()

    def tag(self, repo_name, file_id, tag_name):
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO tags (tag_name) VALUES (?)", (tag_name,))
            cursor.execute("SELECT tag_id FROM tags WHERE tag_name = ?", (tag_name,))
            tid = cursor.fetchone()[0]
            cursor.execute("INSERT OR IGNORE INTO file_tags (file_id, tag_id) VALUES (?, ?)", (file_id, tid))
            self.conn.commit()
            print(f"Tagged {file_id} with {tag_name}")
        finally:
            self._close_db()

    def remove(self, repo_name, file_id):
        try:
            self._connect_db()
            cursor = self.conn.cursor()
            cursor.execute("SELECT repo_path FROM files WHERE file_id = ?", (file_id,))
            res = cursor.fetchone()
            if res:
                p = os.path.join(self.repo_root, res[0])
                if os.path.exists(p): os.remove(p)
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
            cursor.execute("UPDATE files SET status = 'MOVED' WHERE file_id = ? AND repo_name = ?", (file_id, source_repo))
            p = os.path.join(self.repo_root, source[0])
            if os.path.exists(p): os.remove(p)
            cursor.execute("INSERT INTO files (file_id, repo_name, original_path, repo_path) VALUES (?, ?, ?, ?)", 
                           (file_id, target_repo, source[1], os.path.join(target_repo, file_id)))
            self.conn.commit()
            print(f"Moved {file_id} to {target_repo}")
        finally:
            self._close_db()

def main():
    parser = argparse.ArgumentParser(description="Archival Repository Manager")
    subparsers = parser.add_subparsers(dest='command')
    subparsers.add_parser('init').add_argument('repo_name')
    imp = subparsers.add_parser('import'); imp.add_argument('repo_name'); imp.add_argument('folder_path')
    ad = subparsers.add_parser('add'); ad.add_argument('repo_name'); ad.add_argument('file_path')
    tg = subparsers.add_parser('tag'); tg.add_argument('repo_name'); tg.add_argument('file_id'); tg.add_argument('tag_name')
    rm = subparsers.add_parser('remove'); rm.add_argument('repo_name'); rm.add_argument('file_id')
    dt = subparsers.add_parser('del-tag'); dt.add_argument('repo_name'); dt.add_argument('file_id'); dt.add_argument('tag_name')
    mv = subparsers.add_parser('move'); mv.add_argument('source_repo'); mv.add_argument('file_id'); mv.add_argument('target_repo')
    
    # Updated Credential Pool commands
    cs = subparsers.add_parser('add-cred', help='Add a password to the global pool')
    cs.add_argument('password')
    cs.add_argument('--desc', help='Optional description of the credential')
    
    subparsers.add_parser('list-creds', help='List decrypted credentials in the pool')
    
    cd = subparsers.add_parser('del-cred', help='Remove a password from the pool by ID')
    cd.add_argument('cred_id', type=int)

    args = parser.parse_args()
    try:
        manager = RepoManager()
        if args.command == 'init': manager.init(args.repo_name)
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