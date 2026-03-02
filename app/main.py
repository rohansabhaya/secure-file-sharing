from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import FileResponse
import shutil
import uuid
import os
from .utils import generate_signed_url, verify_signature

app = FastAPI()
UPLOAD_DIR = "/workspaces/app/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Mock Metadata Store
metadata_db = {}

@app.post("/upload")
async def upload_file(user_id: str, file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, file_id)
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    metadata = {
        "file_id": file_id,
        "user_id": user_id,
        "filename": file.filename,
        "size": os.path.getsize(file_path),
        "upload_date": "2026-03-02T..." # Use actual datetime
    }
    metadata_db[file_id] = metadata
    return {"status": "success", "file_id": file_id}

@app.get("/sign/{file_id}")
def sign_file(file_id: str, ttl: int = 3600):
    if file_id not in metadata_db:
        raise HTTPException(status_code=404)
    # Log Audit Event here!
    print(f"AUDIT: Signed link generated for {file_id}")
    return {"signed_url": generate_signed_url(file_id, ttl)}

@app.get("/download/{file_id}")
def download_file(file_id: str, expires: int, signature: str):
    if not verify_signature(file_id, expires, signature):
        raise HTTPException(status_code=403, detail="Invalid or expired link")
    
    file_path = os.path.join(UPLOAD_DIR, file_id)
    return FileResponse(file_path, filename=metadata_db[file_id]["filename"])