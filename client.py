#!/usr/bin/env python3
import socket
import json
import base64
import time
import os
from datetime import datetime
from crypto_utils import CryptoUtils
from config import *

class SecureChatClient:
    
    def __init__(self):
        self.crypto = CryptoUtils()
        self.socket = None
        self.session_key = None
        self.client_private_key = None
        self.client_cert = None
        self.ca_cert = None
        self.server_cert = None
        self.seqno = 0
        self.server_seqno = 0
        self.transcript = []
        self.username = None
        
    def connect(self):
        print("=" * 60)
        print("SECURE CHAT CLIENT")
        print("=" * 60)
        
        self.load_certificates()
        
        print(f"\n[*] Connecting to {SERVER_HOST}:{SERVER_PORT}...")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            self.socket.connect((SERVER_HOST, SERVER_PORT))
            print("[✓] Connected to server\n")
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return False
        
        if not self.certificate_exchange():
            return False
        if not self.authenticate():
            return False
        if not self.dh_key_agreement():
            return False
        
        self.chat_loop()
        self.generate_session_receipt()
        return True
    
    def load_certificates(self):
        try:
            self.client_private_key = self.crypto.load_private_key(
                os.path.join(CERTS_DIR, 'client_key.pem')
            )
            self.client_cert = self.crypto.load_certificate(
                os.path.join(CERTS_DIR, 'client_cert.pem')
            )
            self.ca_cert = self.crypto.load_certificate(
                os.path.join(CERTS_DIR, 'ca_cert.pem')
            )
            print("[✓] Certificates loaded")
        except Exception as e:
            print(f"[!] Certificate error: {e}")
            exit(1)
    
    def send_message(self, msg_dict):
        msg_json = json.dumps(msg_dict)
        self.socket.sendall(msg_json.encode() + b'\n')
    
    def receive_message(self):
        data = b''
        while b'\n' not in data:
            chunk = self.socket.recv(4096)
            if not chunk:
                return None
            data += chunk
        return json.loads(data.decode().strip())
    
    def certificate_exchange(self):
        print("[*] Certificate exchange...")
        
        from cryptography.hazmat.primitives import serialization
        client_cert_pem = self.client_cert.public_bytes(serialization.Encoding.PEM).decode()
        
        self.send_message({
            'type': 'hello',
            'client_cert': client_cert_pem,
            'nonce': base64.b64encode(os.urandom(16)).decode()
        })
        
        server_hello = self.receive_message()
        if server_hello['type'] == 'error':
            print(f"[!] Server rejected certificate: {server_hello['message']}")
            return False
        
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            server_cert_pem = server_hello['server_cert'].encode()
            self.server_cert = x509.load_pem_x509_certificate(server_cert_pem, default_backend())
            
            is_valid, msg = self.crypto.verify_certificate(self.server_cert, self.ca_cert)
            if not is_valid:
                print(f"[!] BAD_CERT: {msg}")
                return False
            print("[✓] Server certificate verified")
        except Exception as e:
            print(f"[!] Certificate error: {e}")
            return False
        
        print("[✓] Certificate exchange complete\n")
        return True
    
    def authenticate(self):
        print("[*] Authentication...")
        print("\n1. Register")
        print("2. Login")
        choice = input("Choose (1/2): ").strip()
        
        temp_dh_private = self.crypto.dh_generate_private()
        g, p = DH_GENERATOR, DH_PRIME
        client_A = self.crypto.dh_compute_public(temp_dh_private, g, p)
        
        self.send_message({
            'type': 'dh_register_login_init',
            'g': g,
            'p': p,
            'A': client_A
        })
        
        dh_response = self.receive_message()
        server_B = dh_response['B']
        
        shared_secret = self.crypto.dh_compute_shared_secret(server_B, temp_dh_private, p)
        temp_key = self.crypto.derive_aes_key_from_dh(shared_secret)
        
        if choice == '1':
            email = input("Email: ").strip()
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            
            auth_data = {
                'type': 'register',
                'email': email,
                'username': username,
                'password': password
            }
            self.username = username
        else:
            email = input("Email: ").strip()
            password = input("Password: ").strip()
            
            auth_data = {
                'type': 'login',
                'email': email,
                'password': password
            }
        
        auth_json = json.dumps(auth_data)
        encrypted_data = self.crypto.aes_encrypt(auth_json, temp_key)
        
        self.send_message({
            'type': 'auth_request',
            'encrypted_data': base64.b64encode(encrypted_data).decode()
        })
        
        auth_response = self.receive_message()
        encrypted_response = base64.b64decode(auth_response['encrypted_data'])
        response_json = self.crypto.aes_decrypt(encrypted_response, temp_key)
        response = json.loads(response_json)
        
        if response['success']:
            print(f"[✓] {response['message']}\n")
            if choice == '2':
                self.username = input("Enter your username for chat: ").strip()
            return True
        else:
            print(f"[!] {response['message']}")
            return False
    
    def dh_key_agreement(self):
        print("[*] DH key agreement...")
        
        client_private = self.crypto.dh_generate_private()
        g, p = DH_GENERATOR, DH_PRIME
        client_A = self.crypto.dh_compute_public(client_private, g, p)
        
        self.send_message({
            'type': 'dh_client',
            'g': g,
            'p': p,
            'A': client_A
        })
        
        dh_response = self.receive_message()
        if dh_response['type'] != 'dh_server':
            return False
        
        server_B = dh_response['B']
        shared_secret = self.crypto.dh_compute_shared_secret(server_B, client_private, p)
        self.session_key = self.crypto.derive_aes_key_from_dh(shared_secret)
        
        print("[✓] Session key established\n")
        return True
    
    def chat_loop(self):
        print("[*] Chat session started. Type messages or 'quit' to exit.\n")
        
        import threading
        
        def receive_messages():
            while True:
                try:
                    msg = self.receive_message()
                    if not msg or msg['type'] == 'quit':
                        print("\n[*] Server disconnected")
                        break
                    
                    if msg['type'] == 'msg':
                        if not self.verify_and_decrypt_message(msg):
                            continue
                except:
                    break
        
        receiver = threading.Thread(target=receive_messages, daemon=True)
        receiver.start()
        
        while True:
            try:
                plaintext = input()
                if plaintext.lower() == 'quit':
                    self.send_message({'type': 'quit'})
                    break
                self.send_encrypted_message(plaintext)
            except KeyboardInterrupt:
                break
    
    def send_encrypted_message(self, plaintext):
        self.seqno += 1
        timestamp = int(time.time() * 1000)
        ciphertext = self.crypto.aes_encrypt(plaintext, self.session_key)
        ct_b64 = base64.b64encode(ciphertext).decode()
        
        digest_data = f"{self.seqno}||{timestamp}||{ct_b64}".encode()
        digest = self.crypto.sha256_hash(digest_data)
        signature = self.crypto.rsa_sign(digest, self.client_private_key)
        
        msg = {
            'type': 'msg',
            'seqno': self.seqno,
            'ts': timestamp,
            'ct': ct_b64,
            'sig': base64.b64encode(signature).decode()
        }
        
        self.send_message(msg)
        self.log_transcript(self.seqno, timestamp, ct_b64, base64.b64encode(signature).decode(), 'client')
    
    def verify_and_decrypt_message(self, msg):
        if msg['seqno'] <= self.server_seqno:
            print("[!] REPLAY detected")
            return False
        
        self.server_seqno = msg['seqno']
        ct_b64 = msg['ct']
        
        digest_data = f"{msg['seqno']}||{msg['ts']}||{ct_b64}".encode()
        digest = self.crypto.sha256_hash(digest_data)
        signature = base64.b64decode(msg['sig'])
        
        if not self.crypto.rsa_verify(digest, signature, self.server_cert.public_key()):
            print("[!] SIG_FAIL")
            return False
        
        ciphertext = base64.b64decode(ct_b64)
        plaintext = self.crypto.aes_decrypt(ciphertext, self.session_key)
        
        print(f"Server: {plaintext}")
        self.log_transcript(msg['seqno'], msg['ts'], ct_b64, msg['sig'], 'server')
        return True
    
    def log_transcript(self, seqno, ts, ct, sig, sender):
        fingerprint = self.crypto.get_cert_fingerprint(
            self.server_cert if sender == 'server' else self.client_cert
        )
        self.transcript.append(f"{seqno}|{ts}|{ct}|{sig}|{fingerprint}")
    
    def generate_session_receipt(self):
        if not self.transcript:
            return
        
        transcript_data = '\n'.join(self.transcript)
        transcript_hash = self.crypto.sha256_hash(transcript_data).hex()
        signature = self.crypto.rsa_sign(transcript_hash, self.client_private_key)
        
        receipt = {
            'type': 'receipt',
            'peer': 'client',
            'first_seq': 1,
            'last_seq': len(self.transcript),
            'transcript_sha256': transcript_hash,
            'sig': base64.b64encode(signature).decode()
        }
        
        receipt_file = os.path.join(TRANSCRIPTS_DIR, f'client_receipt_{int(time.time())}.json')
        with open(receipt_file, 'w') as f:
            json.dump(receipt, f, indent=2)
        
        print(f"\n[✓] Session receipt saved: {receipt_file}")

if __name__ == "__main__":
    client = SecureChatClient()
    client.connect()
