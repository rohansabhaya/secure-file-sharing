graph LR
    %% External Actors
    User["👤 Authenticated User"]
    Public["🌍 Public Consumer"]

    %% System Components
    subgraph "🔐 Identity & Security"
        Auth["Auth & JWT Manager"]
    end

    subgraph "⚙️ SecureVault API"
        Upload["Ingestion Manager<br/>(/upload)"]
        Sign["URL Signer<br/>(/sign)"]
        Download["Link Validator<br/>(/download)"]
    end

    subgraph "💾 Persistence & Audit"
        DB[("Metadata &<br/>Audit Logs")]
        Disk[["Vault Storage<br/>(Files)"]]
    end

    %% Step-by-Step Flow
    User -->|1. Credentials| Auth
    Auth -->|2. Issue JWT| User

    User -->|3. File + JWT| Upload
    Upload -->|4. Save Metadata| DB
    Upload -->|5. Store UUID4 File| Disk

    User -->|6. Request Link| Sign
    Sign -->|7. Verify Owner & Log| DB
    Sign -->|8. Return Signed URL| User

    Public -->|9. Use Signed URL| Download
    Download -->|10. Check HMAC & Expiry| Disk
    Disk -->|11. Serve File Stream| Public

    %% Styling for Clarity
    style DB fill:#f5faff,stroke:#007bff,stroke-width:2px
    style Disk fill:#f0fff4,stroke:#28a745,stroke-width:2px
    style Auth fill:#fff5f5,stroke:#dc3545,stroke-width:2px
    style User fill:#ffffff,stroke:#333
    style Public fill:#ffffff,stroke:#333