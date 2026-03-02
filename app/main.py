import os
from time import time
import uuid
import shutil
import hashlib
import logging
import sqlite3
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, status, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

from .database import (
    init_db, save_file_metadata, get_file_metadata, 
    log_audit, get_user_files, get_user, create_user
)
from .utils import (
    generate_signed_url, verify_signature, 
    create_access_token, decode_access_token
)
from .schemas import FileMetadataResponse

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("SecureVault")

# --- Security Configuration ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Dependency to validate the JWT and return the username."""
    try:
        username = decode_access_token(token)
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username
    except Exception as e:
        logger.error(f"JWT Validation Error: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed.")

# --- App Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        init_db()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.critical(f"Critical System Failure: Could not init database: {e}")
    yield

app = FastAPI(
    title="SecureVault API",
    description="Enterprise-grade secure file ingestion and signed retrieval service.",
    lifespan=lifespan
)

# --- Global Exception Handlers ---
@app.exception_handler(sqlite3.Error)
async def database_exception_handler(request: Request, exc: sqlite3.Error):
    """Intercepts all database errors to prevent internal leakage."""
    logger.error(f"Database Error on {request.url.path}: {exc}")
    return JSONResponse(
        status_code=503,
        content={"detail": "Service temporarily unavailable due to database contention."},
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Catch-all for unexpected internal server errors."""
    logger.error(f"Unhandled Exception on {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please contact support."},
    )

# --- Configuration & Constants ---
UPLOAD_DIR = "/workspaces/app/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".txt", ".docx"}

class UserAuth(BaseModel):
    username: str
    password: str

# --- 1. Frontend Route ---
@app.get("/", response_class=HTMLResponse)
async def read_index():
    try:
        with open("app/index.html") as f:
            return f.read()
    except FileNotFoundError:
        logger.error("Frontend index.html missing from app/ directory.")
        raise HTTPException(status_code=404, detail="UI components not found.")

# --- 2. Identity Management ---
@app.post("/register")
async def register_user(auth: UserAuth):
    success = create_user(auth.username, auth.password)
    if not success:
        raise HTTPException(status_code=400, detail="Registration failed: Username already exists.")
    return {"status": "success", "message": "Identity created."}

@app.post("/token")
async def login(auth: UserAuth):
    user = get_user(auth.username)
    if not user:
        raise HTTPException(status_code=401, detail="Account not found.")
    
    hashed_input = hashlib.sha256(auth.password.encode()).hexdigest()
    if user['hashed_password'] != hashed_input:
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    access_token = create_access_token(data={"sub": auth.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- 3. Secure Ingestion ---
@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...), 
    username: str = Depends(get_current_user)
):
    # Validation
    filename = os.path.basename(file.filename)
    file_ext = os.path.splitext(filename)[1].lower()
    
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Extension {file_ext} is prohibited.")

    # Size verification
    file.file.seek(0, os.SEEK_END)
    file_size = file.file.tell()
    file.file.seek(0)
    
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="Payload exceeds maximum allowed size (50MB).")

    # Physical Write with IO Exception Handling
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, file_id)
    
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except IOError as e:
        logger.error(f"IO Error during file write for {filename}: {e}")
        raise HTTPException(status_code=500, detail="Storage failure: Could not commit file to disk.")
    
    save_file_metadata(file_id, username, filename, file_size)
    log_audit(file_id, "FILE_UPLOADED")
    
    return {"status": "success", "file_id": file_id, "filename": filename}

# --- 4. Cryptographic Signer ---
@app.get("/sign/{file_id}")
async def sign_link(
    file_id: str, 
    ttl: int = 3600, 
    username: str = Depends(get_current_user)
):
    data = get_file_metadata(file_id)
    if not data:
        raise HTTPException(status_code=404, detail="Resource not found.")
    
    if data["user_id"] != username:
        logger.warning(f"Unauthorized sign attempt: User {username} tried to access {file_id}")
        raise HTTPException(status_code=403, detail="Access denied: Resource ownership mismatch.")
    
    log_audit(file_id, "LINK_GENERATED")
    url = generate_signed_url(file_id, ttl)
    return {"signed_url": url}

# --- 5. Validated Retrieval ---
@app.get("/download/{file_id}")
async def download_file(file_id: str, expires: int, signature: str):
    if not verify_signature(file_id, expires, signature):
        log_audit(file_id, "DOWNLOAD_DENIED_INVALID_SIG")
        raise HTTPException(status_code=403, detail="Signature invalid or link expired.")
    
    data = get_file_metadata(file_id)
    file_path = os.path.join(UPLOAD_DIR, file_id)
    
    if not os.path.exists(file_path):
        logger.error(f"Data integrity error: File {file_id} metadata exists but physical file is missing.")
        raise HTTPException(status_code=404, detail="Resource physically unavailable.")

    log_audit(file_id, "FILE_DOWNLOADED")
    return FileResponse(file_path, filename=data["filename"])

# --- 6. Dashboards ---
@app.get("/files/me", response_model=List[FileMetadataResponse])
async def list_my_files(username: str = Depends(get_current_user)):
    rows = get_user_files(username)
    return [dict(row) for row in rows]


@app.get("/health")
async def health_check():
    """Critical for DigitalOcean App Platform Liveness Probes."""
    return {"status": "healthy", "timestamp": time.time()}