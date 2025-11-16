"""AES-128(ECB)+PKCS#7 helpers (use library)."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

def generate_key():
    """Generate a random 128-bit AES key."""
    return os.urandom(16)  # 128 bits = 16 bytes

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt plaintext using AES-128-ECB with PKCS#7 padding."""
    # Add PKCS#7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Encrypt with AES-128-ECB
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt ciphertext using AES-128-ECB and remove PKCS#7 padding."""
    # Decrypt with AES-128-ECB
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext
