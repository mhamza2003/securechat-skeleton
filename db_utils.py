# db_utils.py
import mysql.connector
from config import DB_CONFIG
import os
import hashlib

class DatabaseManager:
    
    def __init__(self):
        self.connection = None
        self.cursor = None
    
    def connect(self):
        try:
            self.connection = mysql.connector.connect(**DB_CONFIG)
            self.cursor = self.connection.cursor(dictionary=True)
            return True
        except Exception as e:
            print(f"Database error: {e}")
            return False
    
    def disconnect(self):
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()
    
    def register_user(self, email, username, password):
        try:
            salt = os.urandom(16)
            pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
            query = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
            self.cursor.execute(query, (email, username, salt, pwd_hash))
            self.connection.commit()
            return True, "Registration successful"
        except mysql.connector.IntegrityError:
            return False, "Email or username already exists"
        except Exception as e:
            return False, f"Registration failed: {str(e)}"
    
    def verify_login(self, email, password):
        try:
            query = "SELECT salt, pwd_hash, username FROM users WHERE email = %s"
            self.cursor.execute(query, (email,))
            result = self.cursor.fetchone()
            if not result:
                return False, "User not found", None
            computed_hash = hashlib.sha256(result['salt'] + password.encode()).hexdigest()
            if computed_hash == result['pwd_hash']:
                return True, "Login successful", result['username']
            else:
                return False, "Invalid password", None
        except Exception as e:
            return False, f"Login error: {str(e)}", None
