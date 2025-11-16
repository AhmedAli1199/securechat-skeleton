"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
import hashlib

# Standard DH parameters (RFC 3526 - 2048-bit MODP Group)
DH_P = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024
E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD
3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC
6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F
24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361
C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552
BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905
E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4
C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510
15728E5A8AACAA68FFFFFFFFFFFFFFFF
""".replace('\n', ''), 16)

DH_G = 2

class DHKeyExchange:
    """Diffie-Hellman key exchange handler."""
    
    def __init__(self):
        """Initialize DH parameters."""
        # Create DH parameter numbers
        self.dh_params = dh.DHParameterNumbers(DH_P, DH_G).parameters()
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
    
    def generate_keys(self):
        """Generate DH private/public key pair."""
        self.private_key = self.dh_params.generate_private_key()
        self.public_key = self.private_key.public_key()
        
    def get_public_bytes(self) -> bytes:
        """Get public key as bytes."""
        public_numbers = self.public_key.public_numbers()
        # Convert the public key number to bytes
        return public_numbers.y.to_bytes((public_numbers.y.bit_length() + 7) // 8, 'big')
    
    def compute_shared_secret(self, peer_public_bytes: bytes):
        """Compute shared secret from peer's public key."""
        # Convert peer public bytes back to integer
        peer_public_int = int.from_bytes(peer_public_bytes, 'big')
        
        # Create peer public key object
        peer_public_numbers = dh.DHPublicNumbers(peer_public_int, self.dh_params.parameter_numbers())
        peer_public_key = peer_public_numbers.public_key()
        
        # Compute shared secret
        self.shared_secret = self.private_key.exchange(peer_public_key)
        
    def derive_aes_key(self) -> bytes:
        """Derive 16-byte AES key from shared secret using SHA-256."""
        if self.shared_secret is None:
            raise ValueError("Shared secret not computed yet")
        
        # Hash the shared secret and take first 16 bytes
        hash_digest = hashlib.sha256(self.shared_secret).digest()
        return hash_digest[:16]  # Trunc16(SHA256(Ks))
