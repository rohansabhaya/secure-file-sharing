import pytest
import os
import time
from fastapi.testclient import TestClient
from app.main import app
from app.database import get_db_connection, init_db # Add init_db here

def test_upload_and_persistence():
    with TestClient(app) as client:
        test_user = "rohansabhaya"
        files = {"file": ("test.txt", b"hello world", "text/plain")}
        
        # This triggers the API, which should now have tables ready
        response = client.post(f"/upload?user_id={test_user}", files=files)
        
        assert response.status_code == 200
        data = response.json()
        
        # Direct check to see if it's actually in the DB
        conn = get_db_connection()
        row = conn.execute("SELECT * FROM files WHERE file_id = ?", (data["file_id"],)).fetchone()
        conn.close()
        
        assert row is not None
        assert row["user_id"] == test_user



def test_signature_validity():
    file_id = "test-file-123"
    ttl = 60 # 1 minute
    
    # 1. Generate URL
    url = generate_signed_url(file_id, ttl)
    
    # 2. Extract components (simulating the URL parsing)
    # Format: /download/file_id?expires=EXP&signature=SIG
    parts = url.split("?")
    params = dict(p.split("=") for p in parts[1].split("&"))
    
    # 3. Verify it passes
    assert verify_signature(file_id, int(params["expires"]), params["signature"]) == True

def test_expired_signature():
    file_id = "test-file-123"
    # Create an expiration date in the past
    expired_time = int(time.time()) - 100 
    
    # This should fail
    assert verify_signature(file_id, expired_time, "fake-sig") == False