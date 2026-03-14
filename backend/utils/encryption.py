# backend/utils/encryption.py
# This is the vault's lock — all encryption and decryption lives here

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()


def _get_key() -> bytes:
    """
    Load the 32-byte AES key from the environment.
    
    Why store it in .env?
    Because if the database is ever stolen, the attacker still
    can't decrypt anything without this key. Keep it separate!
    """
    raw = os.environ.get('ENCRYPTION_KEY')
    if not raw:
        raise ValueError("ENCRYPTION_KEY is not set in .env")
    
    # Decode from the base64 string we generated
    key = base64.urlsafe_b64decode(raw)
    
    if len(key) != 32:
        raise ValueError("ENCRYPTION_KEY must decode to exactly 32 bytes for AES-256")
    
    return key


def encrypt_password(plain_text: str) -> str:
    """
    Encrypt a plain text password using AES-256-GCM.
    
    Returns a single string: base64(nonce + ciphertext)
    We combine them so we only need to store one field in the DB.
    
    AES-GCM gives us:
    - Confidentiality: nobody can read the ciphertext
    - Integrity: if someone tampers with the DB, decryption fails
    """
    if not plain_text:
        raise ValueError("Cannot encrypt an empty password")
    
    key = _get_key()
    
    # Generate a fresh 12-byte nonce (IV) for every encryption
    # NEVER reuse a nonce with the same key — this is critical!
    nonce = os.urandom(12)
    
    # Create the AES-GCM cipher
    aesgcm = AESGCM(key)
    
    # Encrypt — returns ciphertext with authentication tag appended
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode('utf-8'), None)
    
    # Combine nonce + ciphertext and encode as base64 for DB storage
    combined = nonce + ciphertext
    return base64.urlsafe_b64encode(combined).decode('utf-8')


def decrypt_password(encrypted_text: str) -> str:
    """
    Decrypt a password that was encrypted with encrypt_password().
    
    Raises an exception if:
    - The data has been tampered with
    - The wrong key is used
    - The data is corrupted
    """
    if not encrypted_text:
        raise ValueError("Cannot decrypt empty data")
    
    key = _get_key()
    
    # Decode from base64
    combined = base64.urlsafe_b64decode(encrypted_text.encode('utf-8'))
    
    # Split back into nonce (first 12 bytes) and ciphertext (the rest)
    nonce = combined[:12]
    ciphertext = combined[12:]
    
    # Decrypt — automatically verifies the authentication tag
    # If anything was tampered with, this raises InvalidTag exception
    aesgcm = AESGCM(key)
    plain_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    
    return plain_bytes.decode('utf-8')


def test_encryption():
    """Quick sanity check — run this to verify your key is working."""
    original = "SuperSecret123!"
    encrypted = encrypt_password(original)
    decrypted = decrypt_password(encrypted)
    
    assert original == decrypted, "Encryption/decryption mismatch!"
    assert original != encrypted, "Password was not encrypted!"
    print(f"Original:  {original}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print("✅ Encryption working correctly!")


if __name__ == '__main__':
    test_encryption()