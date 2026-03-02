# SecureVault | File Ingestion & Retrieval

**SecureVault** is a API service built with **FastAPI**. It is designed for the secure ingestion, metadata management, and cryptographically-signed retrieval of sensitive files. 

The system ensures that file access is isolated by user identity and that sharing is managed via stateless, time-limited signatures.

---

## 🚀 Quick Start

### 1. Install Dependencies
pip install -r requirements.txt


### 2. Run the Server

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
Access the interactive dashboard at: http://localhost:8000

### 3. Run the Robust Test Suite
pytest -v


## 🏗️ Architectural Requirement Fulfillment
### 1. Secure File Ingestion
Implementation: Files are stored in a non-public directory (/app/uploads) outside the web root.

Security: Filenames are unique UUID4 identifiers preventing filename collisions and any directory attacks.

Identity: Every upload is strictly associated with a persistent user_id stored in the SQLite database.

### 2. Link Generation (Signed URLs)
Implementation: The /sign/{file_id} endpoint acts as a cryptographic signer.

HMAC Signing: Utilized HMAC-SHA256 to sign a payload containing the File ID and an expiration timestamp to generate the hash.

Statelessness: Because validation is mathematical, the service can be restarted or scaled horizontally without losing active links.

### 3. File Retrieval & Validation
Expiration: Links are strictly time-bound; the server rejects any request where the current system time exceeds the expires parameter in the URL.

### 4. Audit & Metadata
Owner Dashboard: The /files/me endpoint allows authenticated owners to query their personal "Vault" for filenames, sizes, and upload dates.

Audit Logging: Every critical action (Upload, Sign, Download) is recorded in a write-only audit_logs table for compliance and security monitoring.

## 🔐 Security Hardening Features
### Feature	Implementation Detail
- JWT Identity	
- Stateless JWT manage sessions, replacing insecure URL-based IDs.
- Password Hashing	
- User credentials are protected using SHA-256 hashing. Plain-text passwords never touch the database.
- Global Exceptions	
- Strict whitelist enforcement for file extensions (.pdf, .jpg, .png, etc.) to prevent malicious execution.


## 🗄️ Database & Endpoints
### The Schema
SQLite relational database structure:

users: Persistent identity and hashed credentials.

files: Comprehensive metadata and owner mapping.

audit_logs: Event tracking for SeOps monitoring.

### API Endpoints
- POST	/register	Create a new secure vault identity.	*Public*

- POST	/token	Authenticate and receive a JWT.	*Public*

- POST	/upload	Securely ingest a file to the vault.	*JWT*

- GET	/sign/{id}	Generate a time-limited signed link.	*Owner*

- GET	/download/{id}	Publicly retrieve file via signature.	*Signed*

- GET	/files/me	Query file status and audit history.	*JWT*