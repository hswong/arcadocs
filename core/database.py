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
        db_dir = os.path.dirname(self.db_path)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
            
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('CREATE TABLE IF NOT EXISTS tags (tag_id INTEGER PRIMARY KEY AUTOINCREMENT, tag_name TEXT NOT NULL UNIQUE)')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    repo TEXT NOT NULL,
                    original_path TEXT,
                    repo_path TEXT,
                    status TEXT DEFAULT "ACTIVE",
                    tags TEXT,
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