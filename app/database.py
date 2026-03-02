import sqlite3
import os
import hashlib
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "metadata.db")

def get_db_connection():
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database connection failed: {e}")
        raise

def init_db():
    try:
        with get_db_connection() as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY, hashed_password TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            conn.execute('''CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, filename TEXT NOT NULL, 
                size INTEGER NOT NULL, upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (username))''')
            conn.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, file_id TEXT NOT NULL, 
                event_type TEXT NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES files (file_id))''')
    except sqlite3.Error as e:
        logger.critical(f"Schema initialization failed: {e}")

def create_user(username, password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    try:
        with get_db_connection() as conn:
            conn.execute('INSERT INTO users (username, hashed_password) VALUES (?, ?)', (username, hashed))
            return True
    except sqlite3.IntegrityError:
        return False
    except sqlite3.Error as e:
        logger.error(f"User creation error: {e}")
        return False
        
def get_user(username):
    """Retrieves a user by username for authentication checks."""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

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