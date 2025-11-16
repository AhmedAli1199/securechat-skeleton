"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from datetime import datetime
import os

class PKIValidator:
    """X.509 certificate validation handler."""
    
    def __init__(self, ca_cert_path: str = "certs/ca-cert.pem"):
        """Initialize with CA certificate."""
        self.ca_cert = self._load_ca_cert(ca_cert_path)
    
    def _load_ca_cert(self, ca_cert_path: str):
        """Load CA certificate from file."""
        if not os.path.exists(ca_cert_path):
            raise FileNotFoundError(f"CA certificate not found: {ca_cert_path}")
        
        with open(ca_cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())
    
    def validate_certificate(self, cert_pem_data: bytes, expected_cn: str = None) -> tuple[bool, str]:
        """
        Validate X.509 certificate.
        Returns: (is_valid, error_message)
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem_data)
            
            # 1. Check if certificate is signed by our CA
            if not self._verify_ca_signature(cert):
                return False, "Certificate not signed by trusted CA"
            
            # 2. Check validity period
            if not self._check_validity_period(cert):
                return False, "Certificate expired or not yet valid"
            
            # 3. Check Common Name if specified
            if expected_cn and not self._check_common_name(cert, expected_cn):
                return False, f"Certificate CN does not match expected: {expected_cn}"
            
            return True, "Certificate valid"
            
        except Exception as e:
            return False, f"Certificate parsing error: {str(e)}"
    
    def _verify_ca_signature(self, cert: x509.Certificate) -> bool:
        """Verify that certificate is signed by the CA."""
        try:
            # Get CA public key
            ca_public_key = self.ca_cert.public_key()
            
            # Verify certificate signature
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def _check_validity_period(self, cert: x509.Certificate) -> bool:
        """Check if certificate is within validity period."""
        now = datetime.utcnow()
        return cert.not_valid_before <= now <= cert.not_valid_after
    
    def _check_common_name(self, cert: x509.Certificate, expected_cn: str) -> bool:
        """Check if certificate Common Name matches expected value."""
        try:
            # Check CN in subject
            subject_cn = None
            for attribute in cert.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    subject_cn = attribute.value
                    break
            
            if subject_cn == expected_cn:
                return True
            
            # Also check Subject Alternative Names
            try:
                san_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for san in san_extension.value:
                    if isinstance(san, x509.DNSName) and san.value == expected_cn:
                        return True
            except x509.ExtensionNotFound:
                pass
            
            return False
        except Exception:
            return False
    
    def get_certificate_info(self, cert_pem_data: bytes) -> dict:
        """Extract certificate information."""
        try:
            cert = x509.load_pem_x509_certificate(cert_pem_data)
            
            # Extract subject CN
            subject_cn = None
            for attribute in cert.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    subject_cn = attribute.value
                    break
            
            return {
                "subject_cn": subject_cn,
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": cert.serial_number,
                "not_valid_before": cert.not_valid_before,
                "not_valid_after": cert.not_valid_after,
                "public_key": cert.public_key()
            }
        except Exception as e:
            return {"error": str(e)}

def load_certificate_from_file(cert_path: str) -> bytes:
    """Load certificate PEM data from file."""
    with open(cert_path, "rb") as f:
        return f.read()

def load_private_key_from_file(key_path: str) -> object:
    """Load private key from file."""
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
