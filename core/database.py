import sqlite3
import os

class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Initializes the base schema and runs pending migrations."""
        db_dir = os.path.dirname(self.db_path)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
            
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Create the versioning table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 2. Base Schema (Version 0)
            cursor.execute('CREATE TABLE IF NOT EXISTS tags (tag_id INTEGER PRIMARY KEY AUTOINCREMENT, tag_name TEXT NOT NULL UNIQUE)')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    repo TEXT NOT NULL,
                    file_type TEXT,
                    original_path TEXT,
                    repo_path TEXT,
                    status TEXT DEFAULT "ACTIVE",
                    processing_status TEXT DEFAULT 'READY',
                    tags TEXT DEFAULT '[]',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('CREATE TABLE IF NOT EXISTS file_tags (file_id TEXT NOT NULL, tag_id INTEGER NOT NULL, PRIMARY KEY (file_id, tag_id))')
            cursor.execute('CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY AUTOINCREMENT, encrypted_blob TEXT NOT NULL, description TEXT, created_at TEXT)')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    job_type TEXT NOT NULL, 
                    target_file TEXT NOT NULL, 
                    file_id TEXT,
                    status TEXT DEFAULT "PENDING", 
                    attempts INTEGER DEFAULT 0,
                    last_error TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            self._run_migrations(conn)

    def _run_migrations(self, conn):
        """Sequential list of schema changes."""
        cursor = conn.cursor()
        
        # Get current version
        res = cursor.execute("SELECT MAX(version) FROM schema_version").fetchone()
        current_version = res[0] if res[0] is not None else 0
        
        # Migration 1: Add metadata column to files
        if current_version < 1:
            print("[DB] Applying migration v1: Add metadata to files")
            cursor.execute("ALTER TABLE files ADD COLUMN metadata TEXT DEFAULT '{}'")
            cursor.execute("INSERT INTO schema_version (version) VALUES (1)")
            
        # Migration 2: Add priority to jobs
        if current_version < 2:
            print("[DB] Applying migration v2: Add priority to jobs")
            cursor.execute("ALTER TABLE jobs ADD COLUMN priority INTEGER DEFAULT 0")
            cursor.execute("INSERT INTO schema_version (version) VALUES (2)")

        # Migration 3: Add file_type to files
        if current_version < 3:
            print("[DB] Applying migration v3: Add file_type to files")
            # We check if column exists first to avoid errors if init_db already created it
            cursor.execute("PRAGMA table_info(files)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'file_type' not in columns:
                cursor.execute("ALTER TABLE files ADD COLUMN file_type TEXT")
            cursor.execute("INSERT INTO schema_version (version) VALUES (3)")

        conn.commit()