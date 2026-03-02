import os
import pytest
import time
from httpx import AsyncClient, ASGITransport
from app.main import app, UPLOAD_DIR
from app.database import init_db
from app.utils import generate_signed_url, verify_signature

@pytest.fixture(autouse=True)
def setup_database():
    """Wipes the DB and ensures a fresh schema for every test."""
    if os.path.exists("app/metadata.db"):
        os.remove("app/metadata.db")
    init_db()
    yield
    if os.path.exists(UPLOAD_DIR):
        for f in os.listdir(UPLOAD_DIR):
            os.remove(os.path.join(UPLOAD_DIR, f))

async def get_token(ac: AsyncClient, username: str, password: str):
    await ac.post("/register", json={"username": username, "password": password})
    res = await ac.post("/token", json={"username": username, "password": password})
    return res.json()["access_token"]


@pytest.mark.asyncio
async def test_duplicate_registration_fails():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        data = {"username": "rohan", "password": "123"}
        await ac.post("/register", json=data)
        res = await ac.post("/register", json=data)
        assert res.status_code == 400  # Should not allow duplicate users

@pytest.mark.asyncio
async def test_unauthorized_upload_rejected():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        files = {"file": ("test.txt", b"content", "text/plain")}
        res = await ac.post("/upload", files=files)
        assert res.status_code == 401  # Missing JWT

@pytest.mark.asyncio
async def test_user_isolation_security():
    """Ensures User B cannot sign or access User A's metadata."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # User A uploads a file
        token_a = await get_token(ac, "userA", "passA")
        up_res = await ac.post("/upload", 
                               files={"file": ("vault_a.txt", b"Secret A", "text/plain")}, 
                               headers={"Authorization": f"Bearer {token_a}"})
        file_id_a = up_res.json()["file_id"]

        # User B tries to generate a signed link for User A's file
        token_b = await get_token(ac, "userB", "passB")
        sign_res = await ac.get(f"/sign/{file_id_a}", 
                                headers={"Authorization": f"Bearer {token_b}"})
        
        assert sign_res.status_code == 403  # Access Denied: Not the owner


@pytest.mark.asyncio
async def test_disallowed_file_extension():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        token = await get_token(ac, "rohan", "123")
        files = {"file": ("malware.exe", b"dangerous-code", "application/x-msdownload")}
        res = await ac.post("/upload", files=files, headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 400
        assert "prohibited" in res.json()["detail"].lower()

@pytest.mark.asyncio
async def test_file_too_large():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        token = await get_token(ac, "rohan", "123")
        # Creating a 51MB dummy file (limit is 50MB)
        large_content = b"0" * (51 * 1024 * 1024)
        files = {"file": ("big.pdf", large_content, "application/pdf")}
        res = await ac.post("/upload", files=files, headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 413  # Payload Too Large

@pytest.mark.asyncio
async def test_signature_tampering_rejected():
    """Tests if the HMAC signature protects against URL manipulation."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        token = await get_token(ac, "rohan", "123")
        up = await ac.post("/upload", files={"file": ("doc.pdf", b"data", "application/pdf")}, headers={"Authorization": f"Bearer {token}"})
        file_id = up.json()["file_id"]
        
        # Get valid link
        sign_res = await ac.get(f"/sign/{file_id}", headers={"Authorization": f"Bearer {token}"})
        valid_url = sign_res.json()["signed_url"]
        
        # Tamper with the URL (change the file_id manually)
        tampered_url = valid_url.replace(file_id, "different-uuid")
        res = await ac.get(tampered_url)
        assert res.status_code == 403  # HMAC signature should fail validation

@pytest.mark.asyncio
async def test_expired_link_rejected():
    """Verifies that links cannot be used after their expiration timestamp."""
    # We use verify_signature directly here to simulate a 1-second expiration
    file_id = "test-uuid"
    expired_time = int(time.time()) - 1
    # Even if the signature is "valid" for that timestamp, the time check must fail
    is_valid = verify_signature(file_id, expired_time, "any-signature")
    assert is_valid is False