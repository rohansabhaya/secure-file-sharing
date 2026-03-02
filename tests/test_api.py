import pytest
import os
import time
from fastapi.testclient import TestClient
from app.main import app
from app.database import get_db_connection, init_db

# Setup Constants
TEST_USER = "rohansabhaya"
TEST_FILENAME = "test_document.txt"
TEST_FILE_CONTENT = b"This is a test file content."

init_db()

@pytest.fixture
def auth_headers():
    """Helper to get a valid JWT for the test user."""
    with TestClient(app) as client:
        response = client.post(f"/token?user_id={TEST_USER}")
        token = response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

def test_upload_and_persistence(auth_headers):
    """Test 1: Upload with Auth"""
    with TestClient(app) as client:
        files = {"file": (TEST_FILENAME, TEST_FILE_CONTENT, "text/plain")}
        # We no longer pass user_id in the URL; it's extracted from the token!
        response = client.post("/upload", files=files, headers=auth_headers)
        
        assert response.status_code == 200
        file_id = response.json()["file_id"]

        conn = get_db_connection()
        row = conn.execute("SELECT * FROM files WHERE file_id = ?", (file_id,)).fetchone()
        conn.close()
        assert row is not None

def test_signed_url_flow(auth_headers):
    """Test 2: Full Lifecycle with Auth"""
    with TestClient(app) as client:
        # Upload
        files = {"file": (TEST_FILENAME, TEST_FILE_CONTENT, "text/plain")}
        u_res = client.post("/upload", files=files, headers=auth_headers)
        file_id = u_res.json()["file_id"]

        # Sign
        s_res = client.get(f"/sign/{file_id}?ttl=60", headers=auth_headers)
        assert s_res.status_code == 200
        signed_url = s_res.json()["signed_url"]

        # Download (Public endpoint, no headers needed)
        d_res = client.get(signed_url)
        assert d_res.status_code == 200
        assert d_res.content == TEST_FILE_CONTENT

def test_owner_query_endpoint(auth_headers):
    """Test 3: Query 'me' endpoint"""
    with TestClient(app) as client:
        response = client.get("/files/me", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) > 0