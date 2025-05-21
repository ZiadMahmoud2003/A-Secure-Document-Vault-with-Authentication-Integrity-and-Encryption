# A-Secure-Document-Vault-with-Authentication-Integrity-and-Encryption
# Data Integrity and Secure Document Management System

## Project Description

This project is a Flask-based web application designed to provide a secure platform for user authentication and document management with strong data integrity features. It implements multiple authentication methods, including manual registration with password hashing, OAuth integrations (GitHub, Google, Auth0), and mandatory 2-Factor Authentication (2FA) for all users. The system includes an admin dashboard for managing users and viewing activity logs. Documents uploaded by users are secured using AES encryption, chunking, SHA-256 hashing, HMAC signatures for integrity, and RSA digital signatures for authenticity. Users can also securely share their documents with other registered users.

## Key Features

*   **Multiple Authentication Methods:**
    *   Manual Registration and Login with secure password hashing.
    *   OAuth Integration with GitHub, Google, and Auth0.
*   **Mandatory Two-Factor Authentication (2FA):**
    *   TOTP-based 2FA setup during initial login/signup for all users.
    *   QR code generation for easy setup with authenticator apps.
*   **User Management (Admin Dashboard):**
    *   View and manage all registered users.
    *   Approve or decline pending manual registrations.
    *   Edit user roles (user/admin).
    *   Activate or deactivate user accounts.
    *   View login logs and security settings.
*   **Secure Document Management:**
    *   Upload documents (PDF, DOCX, TXT).
    *   Secure document storage using:
        *   AES Encryption (CBC mode)
        *   Document chunking for handling large files.
        *   SHA-256 hash for content verification.
        *   HMAC-SHA256 signature for integrity protection using a shared secret key.
        *   RSA Digital Signature for authenticity using private/public key pair.
    *   Download documents with integrity checks (HMAC verification and Digital Signature verification) and decryption on the fly.
    *   Delete documents.
    *   Admin ability to edit document metadata (filename, description).
*   **Secure Document Sharing:**
    *   Users can share their owned documents with other registered users.
    *   Recipients can view and download documents shared with them.
*   **Enhanced Security Measures:**
    *   Password policy enforcement (minimum length, complexity requirements).
    *   Account lockout after multiple failed login attempts.
    *   Session management with permanent sessions and security headers (`no-cache`).

## Installation and Setup

1.  **Clone the repository:**
    ```bash
    git clone 
    cd Data-Integrity-Project-final-test
    ```
2.  **Set up the Python Virtual Environment:**
    ```bash
    python -m venv venv
    # On Windows:
    .\venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate
    ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Set up Environment Variables:**
    Create a `.env` file in the project root directory and configure the necessary environment variables. At a minimum, you'll need:
    ```env
    SECRET_KEY=<a_long_random_string>
    DB_USER=<your_db_user>
    DB_PASSWORD=<your_db_password>
    DB_HOST=<your_db_host>
    DB_NAME=<your_db_name>
    AES_KEY=<a_32_byte_string_for_aes_encryption>
    HMAC_KEY=<a_random_string_for_hmac>

    # Optional: For OAuth integrations
    # GITHUB_CLIENT_ID=...
    # GITHUB_CLIENT_SECRET=...
    # GOOGLE_CLIENT_ID=...
    # GOOGLE_CLIENT_ID=...
    # GOOGLE_CLIENT_SECRET=...
    # AUTH0_DOMAIN=...
    # AUTH0_CLIENT_ID=...
    # AUTH0_CLIENT_SECRET=...
    ```
    **Note:** Ensure `AES_KEY` is exactly 32 bytes long after UTF-8 encoding (or padded to 32 bytes as done in `app.py`). Generate strong, random keys for `SECRET_KEY`, `AES_KEY`, and `HMAC_KEY`.
5.  **Generate RSA Keys:**
    You need `private_key.pem` and `public_key.pem` files in the project root for digital signatures. You can generate them using OpenSSL:
    ```bash
    openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
    openssl pkey -in private_key.pem -pubout -out public_key.pem
    ```
    Ensure these files are in the same directory as `app.py`.
6.  **Set up the Database:**
    Ensure your MySQL server is running and you have created the database specified in your `.env` file. The application will create the necessary tables on first run. You might need to run `projectdb.sql` if you have a pre-existing database schema.
7.  **Run the Application:**
    The application runs with HTTPS using self-signed certificates in `cert_files/`. You might need to trust these certificates in your browser for local development or replace them with valid ones for production.
    ```bash
    python run_http.py
    ```
    Or run `app.py` directly which uses `run_http.py` internally:
    ```bash
    python app.py
    ```
    The application should be accessible at `https://127.0.0.1:443/` or `https://localhost:443/`.

## Usage

*   Navigate to the application URL (`https://127.0.0.1:443/`).
*   Sign up for a new account (requires admin approval if manual).
*   Set up 2FA on your first login.
*   Manual users can log in with their username/email and password.
*   OAuth users can log in via GitHub, Google, or Auth0.
*   Once logged in, you can access the home page.
*   Use the "Documents" section to upload, download, delete, and share files.
*   Admins have access to the "/admin" routes for user and system management.

## Screenshots


```markdown
### Login Page
![login](https://github.com/user-attachments/assets/d984126c-4738-4c85-a0ee-0bac64279c47)

### Signup
![Sign Up](https://github.com/user-attachments/assets/178542f5-9776-40a2-a5e1-41bdec601632)


### Home Page
![Home](https://github.com/user-attachments/assets/0547591b-19e1-4aea-8b8b-c44d6f145d87)


### Documents List
![document_list](https://github.com/user-attachments/assets/cdd54cdc-4dff-4e5a-a473-72fa38828800)


### admin home
![admin_home](https://github.com/user-attachments/assets/0dc683c5-9741-4d68-a798-e0ad360a4a75)

### Admin Dashboard
![admin_dashboard](https://github.com/user-attachments/assets/c379d2c2-d6c7-4878-bb45-1997f86a874c)

### Manage users
![Manage_Users](https://github.com/user-attachments/assets/260686d3-dc21-4a04-ab41-c1ddba5ffa7c)

### Logs
![Logs](https://github.com/user-attachments/assets/76808775-156c-4791-a419-45216a2c37f5)

### Securit_setting
![Security Setting](https://github.com/user-attachments/assets/05975c26-71bf-4cab-8f81-e700a82e3d23)

```



## Technologies Used

*   Flask
*   Flask-SQLAlchemy
*   PyMySQL
*   Authlib
*   PyOTP
*   QRCode
*   python-dotenv
*   Werkzeug
*   Cryptography
*   zlib
*   Waitress

