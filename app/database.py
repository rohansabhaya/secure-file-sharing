import sqlite3
import os

# Using an absolute path ensures the DB is created in the correct workspace folder
DB_PATH = "/workspaces/app/metadata.db"

def get_db_connection():
    """Helper to get a connection with row factory for easier data access."""
    conn = sqlite3.connect(DB_PATH)
    # This allows accessing columns by name: row['filename'] instead of row[2]
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Table for File Metadata
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            file_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            size INTEGER NOT NULL,
            upload_date DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Table for Audit Logs (Mandatory Requirement)
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
    """
    Retrieves all files owned by a user, including an 
    aggregated count of how many times a link was generated.
    """
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

def get_audit_logs(file_id):
    """Retrieves the full history of events for a specific file."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT event_type, timestamp FROM audit_logs WHERE file_id = ? ORDER BY timestamp DESC', 
        (file_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return rows