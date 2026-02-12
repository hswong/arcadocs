import os
import hashlib
import shutil
from typing import Optional

class FileManager:
    @staticmethod
    def calculate_id(file_path: str) -> str:
        file_size = os.path.getsize(file_path)
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""): 
                sha256_hash.update(byte_block)
        return f"{file_size}_{sha256_hash.hexdigest()[:16]}"

    @staticmethod
    def get_type(file_path: str) -> str:
        try:
            with open(file_path, 'rb') as f:
                header = f.read(2048)
                if header.startswith(b'PK\x03\x04'): return 'ZIP'
                if header.startswith(b'%PDF'): return 'PDF'
                if header.startswith(b'Rar!'): return 'RAR'
                if header.startswith(b'7z\xbc\xaf\x27\x1c'): return '7Z'
                if b'\x00' in header: return 'BINARY'
                return 'TEXT'
        except Exception: return 'UNKNOWN'