BLACKSITE — Python API starter
A Python/FastAPI backend starter for the BLACKSITE messaging app. It includes:
Account registration and login (hashed passwords, bearer tokens)
User directory and usernames
Private and group conversation creation
Message storage using ciphertext + nonce fields
Public community posts
Disappearing-message expiry metadata
Media upload endpoint (15 MB limit)
WebRTC call-signaling endpoints
Important security truth
This repository is a starter backend, not a production-secure messenger. It does not implement end-to-end encryption by itself. The API accepts opaque ciphertext, but a real client must encrypt messages on the sender's device and decrypt them on the recipient's device using a reviewed protocol and correctly managed keys. Do not call the app end-to-end encrypted until that client implementation has been independently reviewed.
The call endpoints only pass WebRTC signaling data. They do not implement the phone's voice/video interface or a TURN server. The media endpoint stores uploads but does not yet provide secure downloads, scanning, or encryption. Disappearing messages are expired when read, but a scheduled cleanup job is still needed to erase expired records permanently.
Before public launch, add rate limits, email/phone verification, password reset, account deletion, blocking/reporting, moderation, secure media downloads, backups, database migrations, logging, abuse controls, TLS, and independent security review. Do not expose the SQLite database or uploads directory publicly.
Run locally
Python 3.10+ recommended.
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
Create a .env file from .env.example, then set a long random BLACKSITE_SECRET_KEY. Load .env with your preferred environment manager, or export the variables in your terminal.
uvicorn app.main:app --reload
Open:
API: http://127.0.0.1:8000
Interactive API docs: http://127.0.0.1:8000/docs
Push to GitHub
Create a new GitHub repository named blacksite.
Unzip/copy this project into the repository.
Commit and push the files.
Never commit .env, passwords, database files, or secret keys.
Main API routes
Method
Route
Purpose
POST
/auth/register
Create account
POST
/auth/login
Get bearer token
GET
/me
Current account
GET
/users?q=name
Search public usernames
POST
/conversations
Create private/group chat
GET
/conversations
List chats
GET
/conversations/{id}/messages
Read ciphertext messages
POST
/conversations/{id}/messages
Send ciphertext message
POST
/public/posts
Publish public post
GET
/public/posts
Read public feed
POST
/media
Upload image/video/audio
POST/GET
/conversations/{id}/calls/signals
WebRTC signaling
For protected routes, click Authorize in /docs and enter Bearer YOUR_TOKEN if prompted by the docs UI.
Example request flow
Register:
{
  "username": "sampleuser",
  "display_name": "Sample User",
  "password": "use-a-long-unique-password"
}
Login:
{
  "username": "sampleuser",
  "password": "use-a-long-unique-password"
}
Create a one-to-one conversation:
{
  "member_usernames": ["friendname"],
  "title": null,
  "is_group": false
}
Send a message:
{
  "ciphertext": "BASE64_ENCRYPTED_MESSAGE_FROM_CLIENT",
  "nonce": "BASE64_NONCE_FROM_CLIENT",
  "expires_in_seconds": 3600
}
The server does not encrypt plaintext for you. The ciphertext must be produced by the app client before this request is sent.
Deployment
Deploy to a Python host that supports ASGI (for example, Render or Railway), configure the environment variables, and use a managed PostgreSQL database for production. Set BLACKSITE_SECRET_KEY and DATABASE_URL in the host's secret/environment settings. Set CORS_ORIGINS to your actual frontend origin. Use HTTPS only.