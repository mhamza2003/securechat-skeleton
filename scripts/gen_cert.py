#!/usr/bin/env python3
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
from config import CERTS_DIR

def load_ca():
    ca_key_path = os.path.join(CERTS_DIR, 'ca_key.pem')
    ca_cert_path = os.path.join(CERTS_DIR, 'ca_cert.pem')
    
    with open(ca_key_path, 'rb') as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    return ca_private_key, ca_cert

def generate_certificate(common_name, entity_type):
    print(f"\n[*] Generating {entity_type} certificate for '{common_name}'...")
    
    # Load CA
    ca_private_key, ca_cert = load_ca()
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Create certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())
    
    # Save private key
    key_filename = f'{entity_type}_key.pem'
    key_path = os.path.join(CERTS_DIR, key_filename)
    with open(key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    cert_filename = f'{entity_type}_cert.pem'
    cert_path = os.path.join(CERTS_DIR, cert_filename)
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"[✓] {entity_type.capitalize()} private key: {key_path}")
    print(f"[✓] {entity_type.capitalize()} certificate: {cert_path}")

if __name__ == "__main__":
    print("=" * 60)
    print("GENERATING SERVER & CLIENT CERTIFICATES")
    print("=" * 60)
    
    generate_certificate("SecureChat Server", "server")
    generate_certificate("SecureChat Client", "client")
    
    print("\n✓ ALL CERTIFICATES GENERATED SUCCESSFULLY!\n")
