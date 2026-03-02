import hmac
import hashlib
import time

SECRET_KEY = "challenge-super-secret-key" # Use os.getenv in production

def generate_signed_url(file_id: str, ttl: int):
    expiry = int(time.time()) + ttl
    message = f"{file_id}:{expiry}".encode()
    signature = hmac.new(SECRET_KEY.encode(), message, hashlib.sha256).hexdigest()
    return f"/download/{file_id}?expires={expiry}&signature={signature}"

def verify_signature(file_id: str, expiry: int, signature: str):
    if time.time() > expiry:
        return False
    message = f"{file_id}:{expiry}".encode()
    expected_signature = hmac.new(SECRET_KEY.encode(), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_signature, signature)