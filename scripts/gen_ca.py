"""Create Root CA (RSA + self-signed X.509) using cryptography."""

import argparse
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_ca(ca_name: str, output_dir: str = "certs"):
    """Generate a Root CA certificate and private key."""
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sindh"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Karachi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(ca_name.lower().replace(" ", "-")),
        ]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=True,
            crl_sign=True,
            digital_signature=False,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).sign(private_key, hashes.SHA256())
    
    # Save private key
    ca_key_path = os.path.join(output_dir, "ca-key.pem")
    with open(ca_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    ca_cert_path = os.path.join(output_dir, "ca-cert.pem")
    with open(ca_cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"Root CA generated:")
    print(f"  Certificate: {ca_cert_path}")
    print(f"  Private Key: {ca_key_path}")
    print(f"  Subject: {cert.subject}")
    print(f"  Valid from: {cert.not_valid_before}")
    print(f"  Valid until: {cert.not_valid_after}")

def main():
    parser = argparse.ArgumentParser(description='Generate Root CA certificate')
    parser.add_argument('--name', required=True, help='CA name (e.g., "FAST-NU Root CA")')
    parser.add_argument('--output', default='certs', help='Output directory (default: certs)')
    
    args = parser.parse_args()
    generate_ca(args.name, args.output)

if __name__ == "__main__":
    main()
