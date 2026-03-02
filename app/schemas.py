from pydantic import BaseModel
from datetime import datetime

class FileMetadata(BaseModel):
    file_id: str
    user_id: str
    filename: str
    size: int
    upload_date: datetime