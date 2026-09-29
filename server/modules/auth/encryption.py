import logging
from pathlib import Path

from cryptography.fernet import Fernet
from server.config import BASE_DIR, settings

logger = logging.getLogger(__name__)

# Gitignored (data/ is in .gitignore) so the dev key never lands in version control.
_DEV_KEY_PATH = Path(BASE_DIR) / "data" / ".dev_encryption_key"


class Encryption:
    """
    Simple symmetric encryption utility for sensitive data like PATs.
    Uses Fernet with a key from settings.
    """
    _fernet = None

    @classmethod
    def get_instance(cls) -> Fernet:
        if cls._fernet is None:
            key = settings.ENCRYPTION_KEY or cls._dev_key()
            try:
                cls._fernet = Fernet(key.encode())
            except Exception as exc:
                raise ValueError("Invalid ENCRYPTION_KEY; generate one with Fernet.generate_key()") from exc
        return cls._fernet

    @classmethod
    def _dev_key(cls) -> str:
        """Return a stable dev-only key persisted to disk so encrypted credentials
        survive process restarts. Production requires ENCRYPTION_KEY (enforced in
        config validation when DEBUG=False), so this path only runs in development.
        """
        try:
            existing = _DEV_KEY_PATH.read_text(encoding="utf-8").strip()
            if existing:
                Fernet(existing.encode())  # validate before reuse
                return existing
        except FileNotFoundError:
            pass
        except Exception:
            logger.warning(
                "encryption_dev_key_unreadable path=%s; regenerating (previously "
                "encrypted dev credentials will be undecryptable)",
                _DEV_KEY_PATH,
            )

        key = Fernet.generate_key().decode()
        try:
            _DEV_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
            _DEV_KEY_PATH.write_text(key, encoding="utf-8")
            logger.warning(
                "ENCRYPTION_KEY is not set; generated a persistent dev key at %s. "
                "Set ENCRYPTION_KEY in .env for production. DO NOT use this in production.",
                _DEV_KEY_PATH,
            )
        except OSError:
            # Cannot persist (read-only fs etc.) — fall back to in-memory key, but
            # warn loudly that restarts will corrupt encrypted dev credentials.
            logger.warning(
                "ENCRYPTION_KEY is not set and dev key could not be persisted to %s; "
                "using an EPHEMERAL in-memory key. Encrypted credentials will NOT survive "
                "a restart. Set ENCRYPTION_KEY in .env.",
                _DEV_KEY_PATH,
            )
        return key

    @classmethod
    def encrypt(cls, data: str) -> str:
        if not data:
            return ""
        return cls.get_instance().encrypt(data.encode()).decode()

    @classmethod
    def decrypt(cls, encrypted_data: str) -> str:
        if not encrypted_data:
            return ""
        return cls.get_instance().decrypt(encrypted_data.encode()).decode()
