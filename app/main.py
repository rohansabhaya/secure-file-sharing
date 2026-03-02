import os
import uuid
import shutil
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, status
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer

from .database import init_db, save_file_metadata, get_file_metadata, log_audit, get_user_files
from .utils import generate_signed_url, verify_signature, create_access_token, decode_access_token
from .schemas import FileMetadataResponse

from fastapi.responses import HTMLResponse

# --- Security Configuration ---
# This tells FastAPI where the login endpoint is
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Dependency to validate the JWT and return the user_id."""
    user_id = decode_access_token(token)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user_id

# --- App Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI):
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

@app.get("/", response_class=HTMLResponse)
async def read_index():
    with open("app/index.html") as f:
        return f.read()

# --- 1. Authentication Endpoint ---
@app.post("/token")
async def login(user_id: str):
    """
    Simulated login. In a real app, you would verify a password here.
    Returns a JWT that must be used for all subsequent requests.
    """
    access_token = create_access_token(data={"sub": user_id})
    return {"access_token": access_token, "token_type": "bearer"}

# --- 2. Ingestion (Protected) ---
@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...), 
    user_id: str = Depends(get_current_user)
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
    
    save_file_metadata(file_id, user_id, filename, file_size)
    log_audit(file_id, "FILE_UPLOADED")
    
    return {"status": "success", "file_id": file_id, "filename": filename}

# --- 3. Link Generation (Protected) ---
@app.get("/sign/{file_id}")
async def sign_link(
    file_id: str, 
    ttl: int = 3600, 
    user_id: str = Depends(get_current_user)
):
    data = get_file_metadata(file_id)
    if not data:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Ownership Check: Only the owner can generate a signed link
    if data["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="You do not own this file.")
    
    log_audit(file_id, "LINK_GENERATED")
    url = generate_signed_url(file_id, ttl)
    return {"signed_url": url}

# --- 4. File Retrieval (Public via Signature) ---
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

# --- 5. Owner Dashboard (Protected) ---
@app.get("/files/me", response_model=List[FileMetadataResponse])
async def list_my_files(user_id: str = Depends(get_current_user)):
    """Only returns files belonging to the authenticated user."""
    rows = get_user_files(user_id)
    return [dict(row) for row in rows]