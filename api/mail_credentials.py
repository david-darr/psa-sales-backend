"""Encryption boundary for employee Gmail app passwords.

The database stores Fernet tokens. Plaintext reads are permitted only during
the explicit migration window controlled by MAIL_CREDENTIAL_ALLOW_LEGACY.
"""

import os
from binascii import Error as BinasciiError

from cryptography.fernet import Fernet, InvalidToken


TOKEN_PREFIX = "fernet:v1:"


class MailCredentialUnavailable(RuntimeError):
    """The stored credential cannot safely be used."""


def _load_cipher():
    key = os.getenv("MAIL_CREDENTIAL_KEY")
    if not key:
        raise RuntimeError("MAIL_CREDENTIAL_KEY is required")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError, BinasciiError) as exc:
        raise RuntimeError("MAIL_CREDENTIAL_KEY must be a valid Fernet key") from exc


_cipher = _load_cipher()


def is_encrypted(value):
    return bool(value) and value.startswith(TOKEN_PREFIX)


def legacy_reads_enabled():
    return os.getenv("MAIL_CREDENTIAL_ALLOW_LEGACY", "false").strip().lower() == "true"


def encrypt_password(password):
    if not isinstance(password, str) or not password.strip():
        raise ValueError("Email password required")
    return TOKEN_PREFIX + _cipher.encrypt(password.encode("utf-8")).decode("ascii")


def decrypt_password(value):
    if not value:
        return None
    if is_encrypted(value):
        try:
            return _cipher.decrypt(value[len(TOKEN_PREFIX):].encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeError, ValueError) as exc:
            raise MailCredentialUnavailable("Stored email credential cannot be decrypted") from exc
    if legacy_reads_enabled():
        return value
    raise MailCredentialUnavailable("Stored email credential needs migration")
