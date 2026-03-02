from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from typing import List, Optional

# --- Constants for Validation Consistency ---
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".txt", ".docx"}

class FileUploadResponse(BaseModel):
    """Standard response after a successful ingestion."""
    status: str = "success"
    file_id: str
    filename: str

class AuditLogEntry(BaseModel):
    """Individual audit event for a file."""
    event_type: str
    timestamp: datetime
    
    model_config = ConfigDict(from_attributes=True)

class FileMetadataResponse(BaseModel):
    """
    The full status of a file including metadata and 
    aggregated audit stats (Requirement: Audit & Metadata).
    """
    file_id: str
    user_id: str
    filename: str = Field(..., min_length=1, max_length=255)
    size: int = Field(..., gt=0, le=MAX_FILE_SIZE)
    upload_date: datetime
    total_links_generated: int = 0
    
    # Enables compatibility with SQLite Row objects
    model_config = ConfigDict(from_attributes=True)

class SignedUrlResponse(BaseModel):
    """Contract for the cryptographic signer endpoint."""
    file_id: str
    signed_url: str
    expires_at: int

class UserFileDashboard(BaseModel):
    """Top-level response for the owner query (Requirement: Allow owners to query status)."""
    user_id: str
    files: List[FileMetadataResponse]