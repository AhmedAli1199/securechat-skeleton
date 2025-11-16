"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import argparse
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def load_ca_key_and_cert(ca_cert_path="certs/ca-cert.pem", ca_key_path="certs/ca-key.pem"):
    """Load CA certificate and private key."""
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    return ca_cert, ca_key

def generate_cert(common_name: str, output_prefix: str, ca_cert_path="certs/ca-cert.pem", ca_key_path="certs/ca-key.pem"):
    """Generate a certificate signed by the Root CA."""
    
    # Load CA certificate and key
    ca_cert, ca_key = load_ca_key_and_cert(ca_cert_path, ca_key_path)
    
    # Generate private key for the new certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sindh"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Karachi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)  # 1 year
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(common_name),
        ]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=True,
    ).sign(ca_key, hashes.SHA256())
    
    # Save private key
    key_path = f"{output_prefix}-key.pem"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    cert_path = f"{output_prefix}-cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"Certificate generated:")
    print(f"  Certificate: {cert_path}")
    print(f"  Private Key: {key_path}")
    print(f"  Subject: {cert.subject}")
    print(f"  Issuer: {cert.issuer}")
    print(f"  Valid from: {cert.not_valid_before}")
    print(f"  Valid until: {cert.not_valid_after}")

def main():
    parser = argparse.ArgumentParser(description='Generate certificate signed by Root CA')
    parser.add_argument('--cn', required=True, help='Common Name (e.g., "server.local" or "client.local")')
    parser.add_argument('--out', required=True, help='Output prefix (e.g., "certs/server" -> server-cert.pem, server-key.pem)')
    parser.add_argument('--ca-cert', default='certs/ca-cert.pem', help='Path to CA certificate')
    parser.add_argument('--ca-key', default='certs/ca-key.pem', help='Path to CA private key')
    
    args = parser.parse_args()
    
    # Ensure output directory exists
    output_dir = os.path.dirname(args.out)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    generate_cert(args.cn, args.out, args.ca_cert, args.ca_key)

if __name__ == "__main__":
    main()
