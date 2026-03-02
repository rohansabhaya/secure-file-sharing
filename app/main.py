import os
import uuid
import shutil
import hashlib
from contextlib import asynccontextmanager
from typing import List
from pydantic import BaseModel

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, status
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import OAuth2PasswordBearer

from .database import (
    init_db, save_file_metadata, get_file_metadata, 
    log_audit, get_user_files, get_user, create_user
)
from .utils import (
    generate_signed_url, verify_signature, 
    create_access_token, decode_access_token
)
from .schemas import FileMetadataResponse

# --- Security Configuration ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Dependency to validate the JWT and return the username."""
    username = decode_access_token(token)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username

# --- App Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # This creates the 'users' table if it doesn't exist
    init_db()
    yield

app = FastAPI(
    title="Secure File Sharing API",
    description="A production-ready service for signed file transfers.",
    lifespan=lifespan
)

UPLOAD_DIR = "/workspaces/app/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".txt", ".docx"}

# --- 1. Frontend Route ---
@app.get("/", response_class=HTMLResponse)
async def read_index():
    with open("app/index.html") as f:
        return f.read()

class UserAuth(BaseModel):
    username: str
    password: str

# 2. Update the Registration endpoint
@app.post("/register")
async def register_user(auth: UserAuth): # Use the model here
    success = create_user(auth.username, auth.password)
    if not success:
        raise HTTPException(status_code=400, detail="Username already taken.")
    return {"status": "success"}

# 3. Update the Login endpoint
@app.post("/token")
async def login(auth: UserAuth): # Use the model here
    user = get_user(auth.username)
    hashed_input = hashlib.sha256(auth.password.encode()).hexdigest()

    if not user or user['hashed_password'] != hashed_input:
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    access_token = create_access_token(data={"sub": auth.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- 3. Ingestion (Protected) ---
@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...), 
    username: str = Depends(get_current_user)
):
    filename = os.path.basename(file.filename)
    
    file_ext = os.path.splitext(filename)[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Extension not allowed.")

    file.file.seek(0, os.SEEK_END)
    file_size = file.file.tell()
    file.file.seek(0)
    
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large.")

    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, file_id)
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    # We save 'username' as the owner 'user_id'
    save_file_metadata(file_id, username, filename, file_size)
    log_audit(file_id, "FILE_UPLOADED")
    
    return {"status": "success", "file_id": file_id, "filename": filename}

# --- 4. Link Generation (Protected) ---
@app.get("/sign/{file_id}")
async def sign_link(
    file_id: str, 
    ttl: int = 3600, 
    username: str = Depends(get_current_user)
):
    data = get_file_metadata(file_id)
    if not data:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Ownership Check
    if data["user_id"] != username:
        raise HTTPException(status_code=403, detail="Access denied: You do not own this file.")
    
    log_audit(file_id, "LINK_GENERATED")
    url = generate_signed_url(file_id, ttl)
    return {"signed_url": url}

# --- 5. File Retrieval (Public via Signature) ---
@app.get("/download/{file_id}")
async def download_file(file_id: str, expires: int, signature: str):
    if not verify_signature(file_id, expires, signature):
        log_audit(file_id, "DOWNLOAD_DENIED_INVALID_SIG")
        raise HTTPException(status_code=403, detail="Invalid or expired signature")
    
    data = get_file_metadata(file_id)
    file_path = os.path.join(UPLOAD_DIR, file_id)
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Physical file not found")

    log_audit(file_id, "FILE_DOWNLOADED")
    return FileResponse(file_path, filename=data["filename"])

# --- 6. Owner Dashboard (Protected) ---
@app.get("/files/me", response_model=List[FileMetadataResponse])
async def list_my_files(username: str = Depends(get_current_user)):
    """Only returns files belonging to the authenticated user identity."""
    rows = get_user_files(username)
    return [dict(row) for row in rows]