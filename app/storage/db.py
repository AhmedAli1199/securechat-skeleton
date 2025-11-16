"""MySQL users table + salted hashing (no chat storage)."""

import pymysql
import hashlib
import secrets
import os
from dotenv import load_dotenv
from typing import Optional, Tuple

# Load environment variables
load_dotenv()

# Fallback to SQLite if MySQL not available
USE_MYSQL = os.getenv('USE_MYSQL', 'true').lower() == 'true'

if not USE_MYSQL:
    from app.storage.sqlite_db import SQLiteUserDatabase

class UserDatabase:
    """Database handler for user authentication with MySQL/SQLite fallback."""
    
    def __init__(self):
        """Initialize database connection."""
        self.use_mysql = USE_MYSQL
        
        if self.use_mysql:
            self._init_mysql()
        else:
            self.db = SQLiteUserDatabase()
            print("Using SQLite database (fallback)")
    
    def _init_mysql(self):
        """Initialize MySQL connection."""
        self.host = os.getenv('DB_HOST', 'localhost')
        self.port = int(os.getenv('DB_PORT', 3306))
        self.database = os.getenv('DB_NAME', 'securechat')
        self.user = os.getenv('DB_USER', 'scuser')
        self.password = os.getenv('DB_PASSWORD', 'scpass')
        self.connection = None
    
    def connect(self):
        """Establish database connection."""
        if not self.use_mysql:
            return self.db.connect()
        
        try:
            self.connection = pymysql.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=True
            )
            return True
        except Exception as e:
            print(f"MySQL connection failed: {e}")
            print("Falling back to SQLite...")
            self.use_mysql = False
            self.db = SQLiteUserDatabase()
            return self.db.connect()
    
    def disconnect(self):
        """Close database connection."""
        if not self.use_mysql:
            return self.db.disconnect()
        
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def create_tables(self):
        """Create users table if it doesn't exist."""
        if not self.use_mysql:
            return self.db.create_tables()
        
        if not self.connection:
            if not self.connect():
                return False
        
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(64) NOT NULL,
            salt VARCHAR(32) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
        
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(create_table_sql)
            return True
        except Exception as e:
            print(f"Failed to create table: {e}")
            return False
    
    def register_user(self, username: str, password: str) -> bool:
        """Register a new user."""
        if not self.use_mysql:
            return self.db.register_user(username, password)
        
        if not self.connection:
            if not self.connect():
                return False
        
        # Check if user already exists
        if self.user_exists(username):
            print(f"User {username} already exists")
            return False
        
        # Hash password with salt
        password_hash, salt = self._hash_password(password)
        
        insert_sql = "INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)"
        
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(insert_sql, (username, password_hash, salt))
            print(f"User {username} registered successfully")
            return True
        except Exception as e:
            print(f"Failed to register user: {e}")
            return False
    
    def authenticate_user(self, username: str, password: str) -> bool:
        """Authenticate user credentials."""
        if not self.use_mysql:
            return self.db.authenticate_user(username, password)
        
        if not self.connection:
            if not self.connect():
                return False
        
        select_sql = "SELECT password_hash, salt FROM users WHERE username = %s"
        
        try:
            with self.connection.cursor() as cursor:
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
        if not self.use_mysql:
            return self.db.user_exists(username)
        
        if not self.connection:
            if not self.connect():
                return False
        
        select_sql = "SELECT COUNT(*) as count FROM users WHERE username = %s"
        
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(select_sql, (username,))
                result = cursor.fetchone()
                return result['count'] > 0
        except Exception as e:
            print(f"Error checking user existence: {e}")
            return False
    
    def list_users(self):
        """List all users (for testing/admin purposes)."""
        if not self.use_mysql:
            return self.db.list_users()
        
        if not self.connection:
            if not self.connect():
                return []
        
        select_sql = "SELECT id, username, created_at FROM users"
        
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(select_sql)
                return cursor.fetchall()
        except Exception as e:
            print(f"Error listing users: {e}")
            return []
    
    def _hash_password(self, password: str, salt: str = None) -> Tuple[str, str]:
        """Hash password with salt using SHA-256."""
        if salt is None:
            salt = secrets.token_hex(16)  # 32 character hex string
        
        # Combine password and salt
        salted_password = password + salt
        password_hash = hashlib.sha256(salted_password.encode()).hexdigest()
        
        return password_hash, salt

def init_database():
    """Initialize database and create tables."""
    db = UserDatabase()
    if db.connect():
        success = db.create_tables()
        db.disconnect()
        return success
    return False

def main():
    """Command line interface for database operations."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Database operations')
    parser.add_argument('--init', action='store_true', help='Initialize database tables')
    parser.add_argument('--register', nargs=2, metavar=('USERNAME', 'PASSWORD'), help='Register new user')
    parser.add_argument('--list', action='store_true', help='List all users')
    
    args = parser.parse_args()
    
    if args.init:
        if init_database():
            print("Database initialized successfully")
        else:
            print("Database initialization failed")
    
    elif args.register:
        username, password = args.register
        db = UserDatabase()
        if db.connect():
            if db.create_tables():
                if db.register_user(username, password):
                    print(f"User '{username}' registered successfully")
                else:
                    print(f"Failed to register user '{username}'")
            db.disconnect()
    
    elif args.list:
        db = UserDatabase()
        if db.connect():
            users = db.list_users()
            print("Registered users:")
            for user in users:
                print(f"  ID: {user['id']}, Username: {user['username']}, Created: {user['created_at']}")
            db.disconnect()
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
