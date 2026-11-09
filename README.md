import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Boolean,
    Table
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship

# Configure these as GitHub repository secrets / deployment environment variables.
SECRET_KEY = os.getenv("BLACKSITE_SECRET_KEY")
if not SECRET_KEY:
    # Development fallback only. Set BLACKSITE_SECRET_KEY before deployment.
    SECRET_KEY = "development-only-change-this-secret-before-deploying"
ALGORITHM = "HS256"
TOKEN_HOURS = 12
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./blacksite.db")
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

membership = Table(
    "membership", Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("conversation_id", Integer, ForeignKey("conversations.id"), primary_key=True),
)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(32), unique=True, index=True, nullable=False)
    display_name = Column(String(80), nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_public = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Conversation(Base):
    __tablename__ = "conversations"
    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=True)
    is_group = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    members = relationship("User", secondary=membership, backref="conversations")

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id"), index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    # For real E2EE, the client must encrypt content before sending.
    # The server stores ciphertext and never receives plaintext.
    ciphertext = Column(Text, nullable=False)
    nonce = Column(String(256), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=True)

class PublicPost(Base):
    __tablename__ = "public_posts"
    id = Column(Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey("users.id"))
    body = Column(String(2000), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class CallSignal(Base):
    __tablename__ = "call_signals"
    id = Column(Integer, primary_key=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id"))
    sender_id = Column(Integer, ForeignKey("users.id"))
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    payload = Column(Text, nullable=False)  # WebRTC offer/answer/ICE JSON; validate in production.
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(bind=engine)

app = FastAPI(title="BLACKSITE API", version="0.1.0",
              description="Starter API for the BLACKSITE messaging app.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:8000").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    if len(password) < 10:
        raise HTTPException(400, "Password must be at least 10 characters.")
    return pwd_context.hash(password)

def create_token(user_id: int) -> str:
    expiry = datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS)
    return jwt.encode({"sub": str(user_id), "exp": expiry}, SECRET_KEY, algorithm=ALGORITHM)

def current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(data["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(401, "Invalid or expired login token.")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(401, "Account not found.")
    return user

def require_member(conversation: Conversation, user: User):
    if user not in conversation.members:
        raise HTTPException(403, "You are not a member of this conversation.")

class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_.]+$")
    display_name: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=10, max_length=128)

class LoginIn(BaseModel):
    username: str
    password: str

class ConversationIn(BaseModel):
    member_usernames: list[str] = Field(min_length=1, max_length=50)
    title: Optional[str] = Field(default=None, max_length=100)
    is_group: bool = False

class MessageIn(BaseModel):
    ciphertext: str = Field(min_length=1, max_length=20000)
    nonce: str = Field(min_length=1, max_length=256)
    expires_in_seconds: Optional[int] = Field(default=None, ge=60, le=604800)

class PostIn(BaseModel):
    body: str = Field(min_length=1, max_length=2000)

class CallSignalIn(BaseModel):
    payload: str = Field(min_length=1, max_length=20000)
    recipient_username: Optional[str] = None

@app.get("/")
def root():
    return {"app": "BLACKSITE", "status": "running", "docs": "/docs"}

@app.post("/auth/register", status_code=201)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username.lower()).first():
        raise HTTPException(409, "Username is already taken.")
    user = User(username=data.username.lower(), display_name=data.display_name,
                password_hash=hash_password(data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username, "display_name": user.display_name}

@app.post("/auth/login")
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username.lower()).first()
    if not user or not pwd_context.verify(data.password, user.password_hash):
        raise HTTPException(401, "Incorrect username or password.")
    return {"access_token": create_token(user.id), "token_type": "bearer"}

@app.get("/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "username": user.username, "display_name": user.display_name}

@app.get("/users")
def find_users(q: str = "", db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = db.query(User).filter(User.id != user.id, User.is_public == True)
    if q:
        query = query.filter(User.username.contains(q.lower()))
    return [{"username": u.username, "display_name": u.display_name} for u in query.limit(30)]

@app.post("/conversations", status_code=201)
def create_conversation(data: ConversationIn, db: Session = Depends(get_db),
                        user: User = Depends(current_user)):
    names = set(n.lower() for n in data.member_usernames)
    names.add(user.username)
    members = db.query(User).filter(User.username.in_(names)).all()
    found = {m.username for m in members}
    if found != names:
        raise HTTPException(404, "One or more usernames were not found.")
    if not data.is_group and len(members) != 2:
        raise HTTPException(400, "A private conversation must have exactly two members.")
    convo = Conversation(title=data.title, is_group=data.is_group, members=members)
    db.add(convo)
    db.commit()
    db.refresh(convo)
    return {"id": convo.id, "title": convo.title, "is_group": convo.is_group,
            "members": [m.username for m in members]}

@app.get("/conversations")
def list_conversations(db: Session = Depends(get_db), user: User = Depends(current_user)):
    result = []
    for c in user.conversations:
        last = db.query(Message).filter(Message.conversation_id == c.id).order_by(Message.id.desc()).first()
        result.append({"id": c.id, "title": c.title, "is_group": c.is_group,
                       "members": [m.username for m in c.members],
                       "last_message_at": last.created_at.isoformat() if last else None})
    return result

@app.get("/conversations/{conversation_id}/messages")
def get_messages(conversation_id: int, db: Session = Depends(get_db),
                 user: User = Depends(current_user)):
    convo = db.query(Conversation).filter(Conversation.id == conversation_id).first()
    if not convo:
        raise HTTPException(404, "Conversation not found.")
    require_member(convo, user)
    now = datetime.now(timezone.utc)
    messages = db.query(Message).filter(
        Message.conversation_id == conversation_id,
        (Message.expires_at == None) | (Message.expires_at > now)
    ).order_by(Message.id.asc()).limit(200).all()
    return [{"id": m.id, "sender_id": m.sender_id, "ciphertext": m.ciphertext,
             "nonce": m.nonce, "created_at": m.created_at.isoformat(),
             "expires_at": m.expires_at.isoformat() if m.expires_at else None}
            for m in messages]

@app.post("/conversations/{conversation_id}/messages", status_code=201)
def send_message(conversation_id: int, data: MessageIn, db: Session = Depends(get_db),
                 user: User = Depends(current_user)):
    convo = db.query(Conversation).filter(Conversation.id == conversation_id).first()
    if not convo:
        raise HTTPException(404, "Conversation not found.")
    require_member(convo, user)
    expiry = None
    if data.expires_in_seconds:
        expiry = datetime.now(timezone.utc) + timedelta(seconds=data.expires_in_seconds)
    msg = Message(conversation_id=conversation_id, sender_id=user.id,
                  ciphertext=data.ciphertext, nonce=data.nonce, expires_at=expiry)
    db.add(msg)
    db.commit()
    db.refresh(msg)
    return {"id": msg.id, "created_at": msg.created_at.isoformat(),
            "expires_at": expiry.isoformat() if expiry else None}

@app.delete("/conversations/{conversation_id}/messages/{message_id}")
def delete_message(conversation_id: int, message_id: int, db: Session = Depends(get_db),
                   user: User = Depends(current_user)):
    convo = db.query(Conversation).filter(Conversation.id == conversation_id).first()
    if not convo:
        raise HTTPException(404, "Conversation not found.")
    require_member(convo, user)
    msg = db.query(Message).filter(Message.id == message_id,
                                   Message.conversation_id == conversation_id).first()
    if not msg:
        raise HTTPException(404, "Message not found.")
    if msg.sender_id != user.id:
        raise HTTPException(403, "You can only delete your own messages.")
    db.delete(msg)
    db.commit()
    return {"deleted": True}

@app.get("/public/posts")
def public_posts(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.query(PublicPost).order_by(PublicPost.id.desc()).limit(100).all()
    return [{"id": p.id, "username": db.query(User).filter(User.id == p.author_id).first().username,
             "body": p.body, "created_at": p.created_at.isoformat()} for p in rows]

@app.post("/public/posts", status_code=201)
def create_post(data: PostIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    post = PublicPost(author_id=user.id, body=data.body)
    db.add(post)
    db.commit()
    db.refresh(post)
    return {"id": post.id, "body": post.body, "created_at": post.created_at.isoformat()}

@app.post("/conversations/{conversation_id}/calls/signals", status_code=201)
def send_call_signal(conversation_id: int, data: CallSignalIn,
                     db: Session = Depends(get_db), user: User = Depends(current_user)):
    convo = db.query(Conversation).filter(Conversation.id == conversation_id).first()
    if not convo:
        raise HTTPException(404, "Conversation not found.")
    require_member(convo, user)
    recipient_id = None
    if data.recipient_username:
        recipient = next((m for m in convo.members if m.username == data.recipient_username.lower()), None)
        if not recipient:
            raise HTTPException(404, "Recipient is not in this conversation.")
        recipient_id = recipient.id
    signal = CallSignal(conversation_id=conversation_id, sender_id=user.id,
                        recipient_id=recipient_id, payload=data.payload)
    db.add(signal)
    db.commit()
    return {"sent": True}

@app.get("/conversations/{conversation_id}/calls/signals")
def get_call_signals(conversation_id: int, db: Session = Depends(get_db),
                     user: User = Depends(current_user)):
    convo = db.query(Conversation).filter(Conversation.id == conversation_id).first()
    if not convo:
        raise HTTPException(404, "Conversation not found.")
    require_member(convo, user)
    rows = db.query(CallSignal).filter(
        CallSignal.conversation_id == conversation_id,
        CallSignal.sender_id != user.id
    ).order_by(CallSignal.id.asc()).limit(50).all()
    return [{"id": s.id, "sender_id": s.sender_id, "payload": s.payload,
             "created_at": s.created_at.isoformat()} for s in rows]

@app.post("/media")
async def upload_media(file: UploadFile = File(...), user: User = Depends(current_user)):
    allowed = {"image/jpeg", "image/png", "image/webp", "video/mp4", "audio/mpeg", "audio/ogg", "audio/webm"}
    if file.content_type not in allowed:
        raise HTTPException(415, "Unsupported media type.")
    content = await file.read(15 * 1024 * 1024 + 1)
    if len(content) > 15 * 1024 * 1024:
        raise HTTPException(413, "File exceeds 15 MB.")
    # Use random server-side names; never trust the original filename.
    import secrets
    suffix = Path(file.filename or "").suffix[:10]
    name = secrets.token_hex(16) + suffix
    (UPLOAD_DIR / name).write_bytes(content)
    return {"stored": True, "media_id": name,
            "note": "Add authenticated media download and malware scanning before production use."}
