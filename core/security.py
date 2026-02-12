import os
import base64
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class RepoSecurity:
    """Manages the lifecycle of the REPO_KEY, including encryption/decryption with a Master Password."""
    
    def __init__(self, repo_root: str):
        self.repo_root = repo_root
        self.config_path = os.path.join(repo_root, "repo.config")
        self._cipher_suite: Optional[Fernet] = None

    def _get_master_key(self, password: str, salt: bytes) -> bytes:
        """Derives a 32-byte key from a password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def is_initialized(self) -> bool:
        return os.path.exists(self.config_path)

    def initialize(self, password: str):
        """Creates a new REPO_KEY and locks it with the provided master password."""
        if not os.path.exists(self.repo_root):
            os.makedirs(self.repo_root)

        new_repo_key = Fernet.generate_key()
        salt = os.urandom(16)
        
        master_fernet = Fernet(self._get_master_key(password, salt))
        encrypted_repo_key = master_fernet.encrypt(new_repo_key)
        
        with open(self.config_path, "wb") as f:
            f.write(salt + b"||" + encrypted_repo_key)
        
        self._cipher_suite = Fernet(new_repo_key)

    def unlock(self, password: str) -> bool:
        """Attempts to unlock the REPO_KEY using the provided master password."""
        try:
            with open(self.config_path, "rb") as f:
                content = f.read()
                salt, encrypted_repo_key = content.split(b"||")
            
            master_fernet = Fernet(self._get_master_key(password, salt))
            decrypted_repo_key = master_fernet.decrypt(encrypted_repo_key)
            self._cipher_suite = Fernet(decrypted_repo_key)
            return True
        except Exception:
            return False

    def encrypt_data(self, plain_text: str) -> str:
        if not self._cipher_suite:
            raise RuntimeError("Security manager is locked.")
        return self._cipher_suite.encrypt(plain_text.encode()).decode()

    def decrypt_data(self, encrypted_text: str) -> str:
        if not self._cipher_suite:
            raise RuntimeError("Security manager is locked.")
        return self._cipher_suite.decrypt(encrypted_text.encode()).decode()