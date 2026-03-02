import hmac
import hashlib
import time
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt

# --- Constants ---
# In production, these would be loaded from environment variables (os.getenv)
SECRET_KEY = "challenge-super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# --- Identity Management (JWT) ---

def create_access_token(data: dict, expires_delta: timedelta = None):
    """Generates a JWT for user authentication."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc)+ expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    """Validates a JWT and returns the user identity (sub)."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            return None
        return user_id
    except JWTError:
        return None

# --- File Access Management (HMAC) ---

def generate_signed_url(file_id: str, ttl: int):
    """
    Generates a cryptographically signed URL.
    Remains valid even if the service restarts because it is stateless.
    """
    expiry = int(time.time()) + ttl
    message = f"{file_id}:{expiry}".encode()
    
    # Create a signature using the secret key
    signature = hmac.new(SECRET_KEY.encode(), message, hashlib.sha256).hexdigest()
    
    return f"/download/{file_id}?expires={expiry}&signature={signature}"

def verify_signature(file_id: str, expiry: int, signature: str):
    """Validates the HMAC signature and checks for expiration."""
    # 1. Check expiration first
    if time.time() > expiry:
        return False
    
    # 2. Re-calculate the expected signature
    message = f"{file_id}:{expiry}".encode()
    expected_signature = hmac.new(SECRET_KEY.encode(), message, hashlib.sha256).hexdigest()
    
    # 3. Use hmac.compare_digest to prevent timing attacks
    return hmac.compare_digest(expected_signature, signature)