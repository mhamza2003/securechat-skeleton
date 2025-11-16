# crypto_utils.py
import os
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from Crypto.Util.Padding import pad, unpad

class CryptoUtils:
    
    @staticmethod
    def generate_rsa_keypair(key_size=2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        return private_key
    
    @staticmethod
    def dh_generate_private():
        return int.from_bytes(os.urandom(256), 'big')
    
    @staticmethod
    def dh_compute_public(private, g, p):
        return pow(g, private, p)
    
    @staticmethod
    def dh_compute_shared_secret(public, private, p):
        return pow(public, private, p)
    
    @staticmethod
    def derive_aes_key_from_dh(shared_secret):
        secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
        hash_digest = hashlib.sha256(secret_bytes).digest()
        return hash_digest[:16]
    
    @staticmethod
    def aes_encrypt(plaintext, key):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        iv = os.urandom(16)
        padded_plaintext = pad(plaintext, 16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return iv + ciphertext
    
    @staticmethod
    def aes_decrypt(ciphertext, key):
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        plaintext = unpad(padded_plaintext, 16)
        return plaintext.decode()
    
    @staticmethod
    def sha256_hash(data):
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha256(data).digest()
    
    @staticmethod
    def rsa_sign(message, private_key):
        if isinstance(message, str):
            message = message.encode()
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    @staticmethod
    def rsa_verify(message, signature, public_key):
        if isinstance(message, str):
            message = message.encode()
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def load_private_key(filepath, password=None):
        with open(filepath, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=password, backend=default_backend()
            )
        return private_key
    
    @staticmethod
    def load_certificate(filepath):
        with open(filepath, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert
    
    @staticmethod
    def verify_certificate(cert, ca_cert):
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                return False, "Certificate expired or not yet valid"
            return True, "Valid"
        except Exception as e:
            return False, f"Invalid: {str(e)}"
    
    @staticmethod
    def get_cert_fingerprint(cert):
        return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
