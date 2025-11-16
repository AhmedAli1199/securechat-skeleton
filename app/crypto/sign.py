"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import os

def generate_rsa_keys():
    """Generate RSA public/private key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()

def sign_data(data: bytes, private_key) -> bytes:
    """Sign data using RSA private key with PKCS#1 v1.5 padding and SHA-256."""
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    """Verify RSA signature using public key."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def load_private_key_from_pem(pem_data: bytes, password=None):
    """Load RSA private key from PEM format."""
    return serialization.load_pem_private_key(pem_data, password)

def load_public_key_from_pem(pem_data: bytes):
    """Load RSA public key from PEM format."""
    return serialization.load_pem_public_key(pem_data)

def private_key_to_pem(private_key) -> bytes:
    """Convert private key to PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def public_key_to_pem(public_key) -> bytes:
    """Convert public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
