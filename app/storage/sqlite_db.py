"""SQLite fallback database for testing when MySQL is not available."""

import sqlite3
import hashlib
import secrets
import os
from typing import Optional, Tuple

class SQLiteUserDatabase:
    """SQLite database handler for user authentication."""
    
    def __init__(self, db_path: str = "securechat.db"):
        """Initialize database connection."""
        self.db_path = db_path
        self.connection = None
    
    def connect(self):
        """Establish database connection."""
        try:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            return True
        except Exception as e:
            print(f"Database connection failed: {e}")
            return False
    
    def disconnect(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def create_tables(self):
        """Create users table if it doesn't exist."""
        if not self.connection:
            if not self.connect():
                return False
        
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
        
        try:
            cursor = self.connection.cursor()
            cursor.execute(create_table_sql)
            self.connection.commit()
            return True
        except Exception as e:
            print(f"Failed to create table: {e}")
            return False
    
    def _hash_password(self, password: str, salt: str = None) -> Tuple[str, str]:
        """Hash password with salt using SHA-256."""
        if salt is None:
            salt = secrets.token_hex(16)  # 32 character hex string
        
        # Combine password and salt
        salted_password = password + salt
        password_hash = hashlib.sha256(salted_password.encode()).hexdigest()
        
        return password_hash, salt
    
    def register_user(self, username: str, password: str) -> bool:
        """Register a new user."""
        if not self.connection:
            if not self.connect():
                return False
        
        # Check if user already exists
        if self.user_exists(username):
            print(f"User {username} already exists")
            return False
        
        # Hash password with salt
        password_hash, salt = self._hash_password(password)
        
        insert_sql = "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)"
        
        try:
            cursor = self.connection.cursor()
            cursor.execute(insert_sql, (username, password_hash, salt))
            self.connection.commit()
            print(f"User {username} registered successfully")
            return True
        except Exception as e:
            print(f"Failed to register user: {e}")
            return False
    
    def authenticate_user(self, username: str, password: str) -> bool:
        """Authenticate user credentials."""
        if not self.connection:
            if not self.connect():
                return False
        
        select_sql = "SELECT password_hash, salt FROM users WHERE username = ?"
        
        try:
            cursor = self.connection.cursor()
            cursor.execute(select_sql, (username,))
            result = cursor.fetchone()
            
            if not result:
                return False
            
            # Hash provided password with stored salt
            stored_hash = result['password_hash']
            stored_salt = result['salt']
            provided_hash, _ = self._hash_password(password, stored_salt)
            
            return provided_hash == stored_hash
                
        except Exception as e:
            print(f"Authentication error: {e}")
            return False
    
    def user_exists(self, username: str) -> bool:
        """Check if username exists."""
        if not self.connection:
            if not self.connect():
                return False
        
        select_sql = "SELECT COUNT(*) as count FROM users WHERE username = ?"
        
        try:
            cursor = self.connection.cursor()
            cursor.execute(select_sql, (username,))
            result = cursor.fetchone()
            return result['count'] > 0
        except Exception as e:
            print(f"Error checking user existence: {e}")
            return False
    
    def list_users(self):
        """List all users (for testing/admin purposes)."""
        if not self.connection:
            if not self.connect():
                return []
        
        select_sql = "SELECT id, username, created_at FROM users"
        
        try:
            cursor = self.connection.cursor()
            cursor.execute(select_sql)
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error listing users: {e}")
            return []