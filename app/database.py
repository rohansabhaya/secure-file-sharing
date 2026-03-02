import sqlite3
import os
import hashlib

# Dynamic absolute pathing: ensures the DB is next to this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "metadata.db")

def get_db_connection():
    """Helper to get a connection with row factory for easier data access."""
    # check_same_thread=False is mandatory for SQLite + FastAPI
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema including the new Users table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. NEW: Table for Persistent User Identity
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 2. Table for File Metadata
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            file_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            size INTEGER NOT NULL,
            upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (username)
        )
    ''')
    
    # 3. Table for Audit Logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES files (file_id)
        )
    ''')
    
    conn.commit()
    conn.close()

# --- NEW: User Management Functions ---

def get_user(username):
    """Retrieves a user by username for authentication checks."""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def create_user(username, password):
    """Hashes a password and creates a new user record."""
    # Using SHA256 for this assessment. (Production note: Use bcrypt/argon2)
    hashed = hashlib.sha256(password.encode()).hexdigest()
    conn = get_db_connection()
    try:
        conn.execute(
            'INSERT INTO users (username, hashed_password) VALUES (?, ?)', 
            (username, hashed)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False # User already exists
    finally:
        conn.close()

# --- Existing Metadata & Audit Functions ---

def save_file_metadata(file_id, user_id, filename, size):
    """Saves metadata when a new file is uploaded."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO files (file_id, user_id, filename, size) VALUES (?, ?, ?, ?)', 
        (file_id, user_id, filename, size)
    )
    conn.commit()
    conn.close()

def get_file_metadata(file_id):
    """Retrieves metadata for a specific file."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM files WHERE file_id = ?', (file_id,))
    row = cursor.fetchone()
    conn.close()
    return row

def get_user_files(user_id):
    """Retrieves all files owned by a user with link generation counts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    query = '''
        SELECT f.*, 
               (SELECT COUNT(*) FROM audit_logs 
                WHERE file_id = f.file_id AND event_type = 'LINK_GENERATED') as link_count
        FROM files f
        WHERE f.user_id = ?
    '''
    cursor.execute(query, (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def log_audit(file_id, event_type):
    """Records an audit event (Upload, Link Generation, Download)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO audit_logs (file_id, event_type) VALUES (?, ?)', 
        (file_id, event_type)
    )
    conn.commit()
    conn.close()