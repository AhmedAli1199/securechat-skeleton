"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt.""" 

from pydantic import BaseModel
from typing import Optional

class HelloMessage(BaseModel):
    """Client sends certificate to server."""
    msg_type: str = "hello"
    client_cert: str  # Base64 encoded X.509 certificate

class ServerHelloMessage(BaseModel):
    """Server responds with its certificate."""
    msg_type: str = "server_hello"
    server_cert: str  # Base64 encoded X.509 certificate
    
class DHClientMessage(BaseModel):
    """Client sends DH public value."""
    msg_type: str = "dh_client"
    dh_public: str  # Base64 encoded DH public value

class DHServerMessage(BaseModel):
    """Server responds with DH public value."""
    msg_type: str = "dh_server" 
    dh_public: str  # Base64 encoded DH public value

class LoginMessage(BaseModel):
    """Client sends encrypted login credentials."""
    msg_type: str = "login"
    encrypted_data: str  # Base64 encoded AES encrypted username:password
    
class RegisterMessage(BaseModel):
    """Client sends encrypted registration data."""
    msg_type: str = "register"
    encrypted_data: str  # Base64 encoded AES encrypted username:password

class ChatMessage(BaseModel):
    """Encrypted chat message with signature."""
    msg_type: str = "msg"
    seqno: int  # Sequence number for replay protection
    encrypted_text: str  # Base64 encoded AES encrypted message
    signature: str  # Base64 encoded RSA signature of (seqno + encrypted_text)

class ReceiptMessage(BaseModel):
    """Server-signed session receipt."""
    msg_type: str = "receipt"
    session_id: str
    transcript_hash: str  # SHA-256 of complete session transcript
    signature: str  # Server's RSA signature of transcript_hash

class ErrorMessage(BaseModel):
    """Error response."""
    msg_type: str = "error"
    error_code: str  # BAD_CERT, SIG_FAIL, REPLAY, etc.
    message: str

class SuccessMessage(BaseModel):
    """Generic success response."""
    msg_type: str = "success"
    message: str
