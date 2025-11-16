#!/usr/bin/env python3
import socket
import json
import base64
import time
import os
from datetime import datetime
from crypto_utils import CryptoUtils
from db_utils import DatabaseManager
from config import *

class SecureChatServer:
    
    def __init__(self):
        self.crypto = CryptoUtils()
        self.db = DatabaseManager()
        self.socket = None
        self.client_socket = None
        self.session_key = None
        self.server_private_key = None
        self.server_cert = None
        self.ca_cert = None
        self.client_cert = None
        self.seqno = 0
        self.client_seqno = 0
        self.transcript = []
        self.username = None
        
    def start(self):
        print("=" * 60)
        print("SECURE CHAT SERVER")
        print("=" * 60)
        
        self.load_certificates()
        
        if not self.db.connect():
            print("[!] Failed to connect to database")
            return
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((SERVER_HOST, SERVER_PORT))
        self.socket.listen(1)
        
        print(f"\n[*] Server listening on {SERVER_HOST}:{SERVER_PORT}")
        print("[*] Waiting for client...\n")
        
        while True:
            try:
                self.client_socket, addr = self.socket.accept()
                print(f"[+] Client connected from {addr}")
                self.handle_client()
            except KeyboardInterrupt:
                print("\n[*] Server shutting down...")
                break
            except Exception as e:
                print(f"[!] Error: {e}")
            finally:
                self.cleanup_session()
    
    def load_certificates(self):
        try:
            self.server_private_key = self.crypto.load_private_key(
                os.path.join(CERTS_DIR, 'server_key.pem')
            )
            self.server_cert = self.crypto.load_certificate(
                os.path.join(CERTS_DIR, 'server_cert.pem')
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
        self.client_socket.sendall(msg_json.encode() + b'\n')
    
    def receive_message(self):
        data = b''
        while b'\n' not in data:
            chunk = self.client_socket.recv(4096)
            if not chunk:
                return None
            data += chunk
        return json.loads(data.decode().strip())
    
    def handle_client(self):
        try:
            if not self.certificate_exchange():
                return
            if not self.handle_auth():
                return
            if not self.dh_key_agreement():
                return
            self.chat_loop()
            self.generate_session_receipt()
        except Exception as e:
            print(f"[!] Client error: {e}")
    
    def certificate_exchange(self):
        print("\n[*] Certificate exchange...")
        
        client_hello = self.receive_message()
        if client_hello['type'] != 'hello':
            return False
        
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            client_cert_pem = client_hello['client_cert'].encode()
            self.client_cert = x509.load_pem_x509_certificate(client_cert_pem, default_backend())
            
            is_valid, msg = self.crypto.verify_certificate(self.client_cert, self.ca_cert)
            if not is_valid:
                print(f"[!] BAD_CERT: {msg}")
                self.send_message({'type': 'error', 'message': 'BAD_CERT'})
                return False
            print("[✓] Client certificate verified")
        except Exception as e:
            print(f"[!] Certificate error: {e}")
            self.send_message({'type': 'error', 'message': 'BAD_CERT'})
            return False
        
        from cryptography.hazmat.primitives import serialization
        server_cert_pem = self.server_cert.public_bytes(serialization.Encoding.PEM).decode()
        self.send_message({
            'type': 'server_hello',
            'server_cert': server_cert_pem,
            'nonce': base64.b64encode(os.urandom(16)).decode()
        })
        
        print("[✓] Certificate exchange complete\n")
        return True
    
    def handle_auth(self):
        print("[*] Waiting for auth...")
        
        temp_dh_private = self.crypto.dh_generate_private()
        dh_init = self.receive_message()
        
        if dh_init['type'] != 'dh_register_login_init':
            return False
        
        g, p, client_A = dh_init['g'], dh_init['p'], dh_init['A']
        server_B = self.crypto.dh_compute_public(temp_dh_private, g, p)
        
        self.send_message({'type': 'dh_register_login_response', 'B': server_B})
        
        shared_secret = self.crypto.dh_compute_shared_secret(client_A, temp_dh_private, p)
        temp_key = self.crypto.derive_aes_key_from_dh(shared_secret)
        
        auth_msg = self.receive_message()
        encrypted_data = base64.b64decode(auth_msg['encrypted_data'])
        auth_json = self.crypto.aes_decrypt(encrypted_data, temp_key)
        auth_data = json.loads(auth_json)
        
        if auth_data['type'] == 'register':
            success, msg = self.db.register_user(
                auth_data['email'],
                auth_data['username'],
                auth_data['password']
            )
            self.username = auth_data['username'] if success else None
            encrypted_response = self.crypto.aes_encrypt(json.dumps({'success': success, 'message': msg}), temp_key)
            self.send_message({'type': 'auth_response', 'encrypted_data': base64.b64encode(encrypted_response).decode()})
            
            if success:
                print(f"[✓] User registered: {self.username}\n")
            return success
            
        elif auth_data['type'] == 'login':
            success, msg, username = self.db.verify_login(auth_data['email'], auth_data['password'])
            self.username = username if success else None
            encrypted_response = self.crypto.aes_encrypt(json.dumps({'success': success, 'message': msg}), temp_key)
            self.send_message({'type': 'auth_response', 'encrypted_data': base64.b64encode(encrypted_response).decode()})
            
            if success:
                print(f"[✓] User logged in: {self.username}\n")
            return success
        
        return False
    
    def dh_key_agreement(self):
        print("[*] DH key agreement...")
        
        dh_msg = self.receive_message()
        if dh_msg['type'] != 'dh_client':
            return False
        
        g, p, client_A = dh_msg['g'], dh_msg['p'], dh_msg['A']
        server_private = self.crypto.dh_generate_private()
        server_B = self.crypto.dh_compute_public(server_private, g, p)
        
        self.send_message({'type': 'dh_server', 'B': server_B})
        
        shared_secret = self.crypto.dh_compute_shared_secret(client_A, server_private, p)
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
                        print("\n[*] Client disconnected")
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
        signature = self.crypto.rsa_sign(digest, self.server_private_key)
        
        msg = {
            'type': 'msg',
            'seqno': self.seqno,
            'ts': timestamp,
            'ct': ct_b64,
            'sig': base64.b64encode(signature).decode()
        }
        
        self.send_message(msg)
        self.log_transcript(self.seqno, timestamp, ct_b64, base64.b64encode(signature).decode(), 'server')
    
    def verify_and_decrypt_message(self, msg):
        if msg['seqno'] <= self.client_seqno:
            print("[!] REPLAY detected")
            return False
        
        self.client_seqno = msg['seqno']
        ct_b64 = msg['ct']
        
        digest_data = f"{msg['seqno']}||{msg['ts']}||{ct_b64}".encode()
        digest = self.crypto.sha256_hash(digest_data)
        signature = base64.b64decode(msg['sig'])
        
        if not self.crypto.rsa_verify(digest, signature, self.client_cert.public_key()):
            print("[!] SIG_FAIL")
            return False
        
        ciphertext = base64.b64decode(ct_b64)
        plaintext = self.crypto.aes_decrypt(ciphertext, self.session_key)
        
        print(f"{self.username}: {plaintext}")
        self.log_transcript(msg['seqno'], msg['ts'], ct_b64, msg['sig'], 'client')
        return True
    
    def log_transcript(self, seqno, ts, ct, sig, sender):
        fingerprint = self.crypto.get_cert_fingerprint(
            self.client_cert if sender == 'client' else self.server_cert
        )
        self.transcript.append(f"{seqno}|{ts}|{ct}|{sig}|{fingerprint}")
    
    def generate_session_receipt(self):
        if not self.transcript:
            return
        
        transcript_data = '\n'.join(self.transcript)
        transcript_hash = self.crypto.sha256_hash(transcript_data).hex()
        signature = self.crypto.rsa_sign(transcript_hash, self.server_private_key)
        
        receipt = {
            'type': 'receipt',
            'peer': 'server',
            'first_seq': 1,
            'last_seq': len(self.transcript),
            'transcript_sha256': transcript_hash,
            'sig': base64.b64encode(signature).decode()
        }
        
        receipt_file = os.path.join(TRANSCRIPTS_DIR, f'server_receipt_{int(time.time())}.json')
        with open(receipt_file, 'w') as f:
            json.dump(receipt, f, indent=2)
        
        print(f"\n[✓] Session receipt saved: {receipt_file}")
    
    def cleanup_session(self):
        self.seqno = 0
        self.client_seqno = 0
        self.transcript = []
        self.session_key = None
        if self.client_socket:
            self.client_socket.close()

if __name__ == "__main__":
    server = SecureChatServer()
    server.start()
