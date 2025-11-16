"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import threading
import uuid
import os
from dotenv import load_dotenv

from app.common.protocol import *
from app.common.utils import *
from app.crypto.aes import *
from app.crypto.dh import *
from app.crypto.pki import *
from app.crypto.sign import *
from app.storage.db import UserDatabase
from app.storage.transcript import TranscriptLogger

# Load environment variables
load_dotenv()

class SecureChatServer:
    """Secure chat server implementation."""
    
    def __init__(self):
        """Initialize server."""
        self.host = os.getenv('SERVER_HOST', 'localhost')
        self.port = int(os.getenv('SERVER_PORT', 8443))
        self.ca_cert_path = os.getenv('CA_CERT_PATH', 'certs/ca-cert.pem')
        self.server_cert_path = os.getenv('SERVER_CERT_PATH', 'certs/server-cert.pem')
        self.server_key_path = os.getenv('SERVER_KEY_PATH', 'certs/server-key.pem')
        
        # Load server certificate and private key
        self.server_cert_data = load_certificate_from_file(self.server_cert_path)
        self.server_private_key = load_private_key_from_file(self.server_key_path)
        
        # Initialize PKI validator
        self.pki_validator = PKIValidator(self.ca_cert_path)
        
        # Initialize database
        self.db = UserDatabase()
        self.db.connect()
        self.db.create_tables()
        
        print(f"Server initialized on {self.host}:{self.port}")
    
    def start(self):
        """Start the server."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"Server listening on {self.host}:{self.port}")
            
            while True:
                client_socket, client_address = server_socket.accept()
                print(f"New connection from {client_address}")
                
                # Handle client in separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\nServer shutting down...")
        finally:
            server_socket.close()
            self.db.disconnect()
    
    def handle_client(self, client_socket, client_address):
        """Handle individual client connection."""
        session_id = str(uuid.uuid4())
        transcript = TranscriptLogger(session_id)
        
        try:
            print(f"Handling client {client_address} (session: {session_id})")
            
            # Protocol state
            client_cert_data = None
            dh = DHKeyExchange()
            aes_key = None
            authenticated_user = None
            seqno = 0
            
            while True:
                # Receive message
                data = client_socket.recv(4096)
                if not data:
                    break
                
                try:
                    message_json = data.decode('utf-8')
                    message_dict = json.loads(message_json)
                    msg_type = message_dict.get('msg_type', '')
                    
                    transcript.log_event("message_received", {
                        "from": str(client_address),
                        "msg_type": msg_type,
                        "raw_data": message_json[:100] + "..." if len(message_json) > 100 else message_json
                    })
                    
                    if msg_type == 'hello':
                        response = self.handle_hello(message_dict, transcript)
                        client_cert_data = message_dict.get('client_cert')
                        
                    elif msg_type == 'dh_client':
                        response = self.handle_dh_client(message_dict, dh, transcript)
                        if response.msg_type == 'dh_server':
                            # DH complete, derive AES key
                            aes_key = dh.derive_aes_key()
                            transcript.log_event("key_derived", {"key_length": len(aes_key)})
                        
                    elif msg_type == 'login':
                        if aes_key is None:
                            response = ErrorMessage(error_code="NO_KEY", message="Key exchange required first")
                        else:
                            response, user = self.handle_login(message_dict, aes_key, transcript)
                            if user:
                                authenticated_user = user
                        
                    elif msg_type == 'register':
                        if aes_key is None:
                            response = ErrorMessage(error_code="NO_KEY", message="Key exchange required first")
                        else:
                            response = self.handle_register(message_dict, aes_key, transcript)
                        
                    elif msg_type == 'msg':
                        if authenticated_user is None:
                            response = ErrorMessage(error_code="NOT_AUTH", message="Authentication required")
                        elif aes_key is None:
                            response = ErrorMessage(error_code="NO_KEY", message="Key exchange required")
                        else:
                            response, seqno = self.handle_chat_message(message_dict, aes_key, seqno, client_cert_data, transcript)
                        
                    else:
                        response = ErrorMessage(error_code="UNKNOWN_MSG", message=f"Unknown message type: {msg_type}")
                    
                    # Send response
                    response_json = response.model_dump_json()
                    client_socket.send(response_json.encode('utf-8'))
                    
                    transcript.log_event("message_sent", {
                        "to": str(client_address),
                        "msg_type": response.msg_type,
                        "raw_data": response_json[:100] + "..." if len(response_json) > 100 else response_json
                    })
                    
                except json.JSONDecodeError:
                    error_response = ErrorMessage(error_code="INVALID_JSON", message="Invalid JSON format")
                    client_socket.send(error_response.model_dump_json().encode('utf-8'))
                except Exception as e:
                    error_response = ErrorMessage(error_code="SERVER_ERROR", message=f"Server error: {str(e)}")
                    client_socket.send(error_response.model_dump_json().encode('utf-8'))
                    print(f"Error handling client {client_address}: {e}")
            
            # Generate session receipt
            if authenticated_user:
                transcript.close_session()
                receipt = self.generate_session_receipt(session_id, transcript)
                client_socket.send(receipt.model_dump_json().encode('utf-8'))
                
        except Exception as e:
            print(f"Error in client handler: {e}")
        finally:
            client_socket.close()
            transcript.close_session()
            print(f"Client {client_address} disconnected")
    
    def handle_hello(self, message_dict, transcript):
        """Handle client hello message."""
        try:
            hello_msg = HelloMessage(**message_dict)
            client_cert_data = b64d(hello_msg.client_cert)
            
            # Validate client certificate
            valid, error_msg = self.pki_validator.validate_certificate(client_cert_data, "client.local")
            
            if not valid:
                transcript.log_error("BAD_CERT", error_msg)
                return ErrorMessage(error_code="BAD_CERT", message=error_msg)
            
            transcript.log_event("client_cert_validated", {"client_cn": "client.local"})
            
            # Send server certificate
            return ServerHelloMessage(server_cert=b64e(self.server_cert_data))
            
        except Exception as e:
            return ErrorMessage(error_code="HELLO_ERROR", message=f"Hello processing error: {str(e)}")
    
    def handle_dh_client(self, message_dict, dh, transcript):
        """Handle DH key exchange from client."""
        try:
            dh_msg = DHClientMessage(**message_dict)
            client_public_bytes = b64d(dh_msg.dh_public)
            
            # Generate server DH keys
            dh.generate_keys()
            server_public_bytes = dh.get_public_bytes()
            
            # Compute shared secret
            dh.compute_shared_secret(client_public_bytes)
            
            transcript.log_key_exchange("dh_complete", b64e(server_public_bytes))
            
            return DHServerMessage(dh_public=b64e(server_public_bytes))
            
        except Exception as e:
            return ErrorMessage(error_code="DH_ERROR", message=f"DH error: {str(e)}")
    
    def handle_login(self, message_dict, aes_key, transcript):
        """Handle user login."""
        try:
            login_msg = LoginMessage(**message_dict)
            encrypted_creds = b64d(login_msg.encrypted_data)
            
            # Decrypt credentials
            decrypted_creds = decrypt(encrypted_creds, aes_key).decode('utf-8')
            username, password = decrypted_creds.split(':', 1)
            
            # Authenticate
            if self.db.authenticate_user(username, password):
                transcript.log_authentication(username, True)
                return SuccessMessage(message=f"Welcome {username}!"), username
            else:
                transcript.log_authentication(username, False)
                return ErrorMessage(error_code="AUTH_FAIL", message="Invalid credentials"), None
                
        except Exception as e:
            return ErrorMessage(error_code="LOGIN_ERROR", message=f"Login error: {str(e)}"), None
    
    def handle_register(self, message_dict, aes_key, transcript):
        """Handle user registration."""
        try:
            register_msg = RegisterMessage(**message_dict)
            encrypted_creds = b64d(register_msg.encrypted_data)
            
            # Decrypt credentials
            decrypted_creds = decrypt(encrypted_creds, aes_key).decode('utf-8')
            username, password = decrypted_creds.split(':', 1)
            
            # Register user
            if self.db.register_user(username, password):
                transcript.log_event("user_registered", {"username": username})
                return SuccessMessage(message=f"User {username} registered successfully")
            else:
                return ErrorMessage(error_code="REG_FAIL", message="Registration failed")
                
        except Exception as e:
            return ErrorMessage(error_code="REGISTER_ERROR", message=f"Registration error: {str(e)}")
    
    def handle_chat_message(self, message_dict, aes_key, expected_seqno, client_cert_data, transcript):
        """Handle chat message."""
        try:
            chat_msg = ChatMessage(**message_dict)
            
            # Check sequence number for replay protection
            if chat_msg.seqno != expected_seqno + 1:
                transcript.log_error("REPLAY", f"Invalid sequence number: {chat_msg.seqno}")
                return ErrorMessage(error_code="REPLAY", message="Invalid sequence number"), expected_seqno
            
            # Verify signature
            if client_cert_data:
                cert_info = self.pki_validator.get_certificate_info(client_cert_data)
                client_public_key = cert_info.get('public_key')
                
                if client_public_key:
                    # Create data to verify: seqno + encrypted_text
                    verify_data = f"{chat_msg.seqno}{chat_msg.encrypted_text}".encode()
                    signature_bytes = b64d(chat_msg.signature)
                    
                    if not verify_signature(verify_data, signature_bytes, client_public_key):
                        transcript.log_error("SIG_FAIL", "Message signature verification failed")
                        return ErrorMessage(error_code="SIG_FAIL", message="Invalid signature"), expected_seqno
            
            # Decrypt message
            encrypted_text = b64d(chat_msg.encrypted_text)
            decrypted_text = decrypt(encrypted_text, aes_key).decode('utf-8')
            
            transcript.log_message("client_to_server", "chat", chat_msg.encrypted_text, chat_msg.signature, chat_msg.seqno)
            
            print(f"Received message: {decrypted_text}")
            
            # Echo response (for simple chat)
            response_text = f"Echo: {decrypted_text}"
            encrypted_response = encrypt(response_text.encode(), aes_key)
            
            # Sign the response
            response_seqno = expected_seqno + 1
            sign_data_str = f"{response_seqno}{b64e(encrypted_response)}".encode()
            signature = sign_data(sign_data_str, self.server_private_key)
            
            transcript.log_message("server_to_client", "echo", b64e(encrypted_response), b64e(signature), response_seqno)
            
            return ChatMessage(
                seqno=response_seqno,
                encrypted_text=b64e(encrypted_response),
                signature=b64e(signature)
            ), response_seqno
            
        except Exception as e:
            return ErrorMessage(error_code="MSG_ERROR", message=f"Message error: {str(e)}"), expected_seqno
    
    def generate_session_receipt(self, session_id, transcript):
        """Generate signed session receipt."""
        try:
            transcript_hash = transcript.get_transcript_hash()
            
            # Sign the transcript hash
            signature = sign_data(transcript_hash.encode(), self.server_private_key)
            
            return ReceiptMessage(
                session_id=session_id,
                transcript_hash=transcript_hash,
                signature=b64e(signature)
            )
        except Exception as e:
            return ErrorMessage(error_code="RECEIPT_ERROR", message=f"Receipt generation error: {str(e)}")

def main():
    """Main server entry point."""
    server = SecureChatServer()
    server.start()

if __name__ == "__main__":
    main()
