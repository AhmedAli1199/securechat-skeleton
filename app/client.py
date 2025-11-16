"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
import getpass
from dotenv import load_dotenv

from app.common.protocol import *
from app.common.utils import *
from app.crypto.aes import *
from app.crypto.dh import *
from app.crypto.pki import *
from app.crypto.sign import *

# Load environment variables
load_dotenv()

class SecureChatClient:
    """Secure chat client implementation."""
    
    def __init__(self):
        """Initialize client."""
        self.host = os.getenv('SERVER_HOST', 'localhost')
        self.port = int(os.getenv('SERVER_PORT', 8443))
        self.ca_cert_path = os.getenv('CA_CERT_PATH', 'certs/ca-cert.pem')
        self.client_cert_path = os.getenv('CLIENT_CERT_PATH', 'certs/client-cert.pem')
        self.client_key_path = os.getenv('CLIENT_KEY_PATH', 'certs/client-key.pem')
        
        # Load client certificate and private key
        self.client_cert_data = load_certificate_from_file(self.client_cert_path)
        self.client_private_key = load_private_key_from_file(self.client_key_path)
        
        # Initialize PKI validator
        self.pki_validator = PKIValidator(self.ca_cert_path)
        
        # Connection state
        self.socket = None
        self.dh = DHKeyExchange()
        self.aes_key = None
        self.authenticated = False
        self.seqno = 0
        
        print("Client initialized")
    
    def connect(self):
        """Connect to the server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"Connected to server {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from server."""
        if self.socket:
            self.socket.close()
            print("Disconnected from server")
    
    def send_message(self, message):
        """Send a message to the server."""
        message_json = message.model_dump_json()
        self.socket.send(message_json.encode('utf-8'))
    
    def receive_message(self):
        """Receive and parse message from server."""
        data = self.socket.recv(4096)
        if not data:
            return None
        
        message_json = data.decode('utf-8')
        return json.loads(message_json)
    
    def handshake(self):
        """Perform the initial handshake with server."""
        print("\n=== Starting Handshake ===")
        
        # Step 1: Send HELLO with client certificate
        print("1. Sending client certificate...")
        hello_msg = HelloMessage(client_cert=b64e(self.client_cert_data))
        self.send_message(hello_msg)
        
        # Receive SERVER_HELLO
        response = self.receive_message()
        if response.get('msg_type') != 'server_hello':
            print(f"Handshake failed: {response}")
            return False
        
        server_hello = ServerHelloMessage(**response)
        server_cert_data = b64d(server_hello.server_cert)
        
        # Validate server certificate
        valid, error_msg = self.pki_validator.validate_certificate(server_cert_data, "server.local")
        if not valid:
            print(f"Server certificate validation failed: {error_msg}")
            return False
        
        print("✓ Server certificate validated")
        
        # Step 2: Diffie-Hellman Key Exchange
        print("2. Performing key exchange...")
        self.dh.generate_keys()
        client_public_bytes = self.dh.get_public_bytes()
        
        dh_client_msg = DHClientMessage(dh_public=b64e(client_public_bytes))
        self.send_message(dh_client_msg)
        
        # Receive DH_SERVER
        response = self.receive_message()
        if response.get('msg_type') != 'dh_server':
            print(f"Key exchange failed: {response}")
            return False
        
        dh_server = DHServerMessage(**response)
        server_public_bytes = b64d(dh_server.dh_public)
        
        # Compute shared secret and derive AES key
        self.dh.compute_shared_secret(server_public_bytes)
        self.aes_key = self.dh.derive_aes_key()
        
        print("✓ Shared secret established")
        print("=== Handshake Complete ===\n")
        return True
    
    def authenticate(self):
        """Authenticate with the server."""
        print("\n=== Authentication ===")
        
        while True:
            print("1. Login")
            print("2. Register")
            choice = input("Choose option (1/2): ").strip()
            
            if choice not in ['1', '2']:
                print("Invalid choice. Please select 1 or 2.")
                continue
            
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            
            # Encrypt credentials
            credentials = f"{username}:{password}"
            encrypted_creds = encrypt(credentials.encode(), self.aes_key)
            
            if choice == '1':
                # Login
                login_msg = LoginMessage(encrypted_data=b64e(encrypted_creds))
                self.send_message(login_msg)
                
                response = self.receive_message()
                if response.get('msg_type') == 'success':
                    print(f"✓ {response.get('message')}")
                    self.authenticated = True
                    return True
                else:
                    print(f"✗ Login failed: {response.get('message')}")
                    
            else:
                # Register
                register_msg = RegisterMessage(encrypted_data=b64e(encrypted_creds))
                self.send_message(register_msg)
                
                response = self.receive_message()
                if response.get('msg_type') == 'success':
                    print(f"✓ {response.get('message')}")
                    print("Please login with your new credentials.")
                else:
                    print(f"✗ Registration failed: {response.get('message')}")
            
            # Ask if user wants to try again
            if not self.authenticated:
                retry = input("Try again? (y/n): ").strip().lower()
                if retry != 'y':
                    return False
    
    def chat_loop(self):
        """Main chat loop."""
        print("\n=== Secure Chat ===")
        print("Type 'quit' to exit")
        print("-" * 30)
        
        while True:
            try:
                message_text = input("You: ").strip()
                
                if message_text.lower() == 'quit':
                    break
                
                if not message_text:
                    continue
                
                # Encrypt message
                encrypted_text = encrypt(message_text.encode(), self.aes_key)
                
                # Increment sequence number
                self.seqno += 1
                
                # Sign message (seqno + encrypted_text)
                sign_data_str = f"{self.seqno}{b64e(encrypted_text)}"
                signature = sign_data(sign_data_str.encode(), self.client_private_key)
                
                # Send chat message
                chat_msg = ChatMessage(
                    seqno=self.seqno,
                    encrypted_text=b64e(encrypted_text),
                    signature=b64e(signature)
                )
                self.send_message(chat_msg)
                
                # Receive response
                response = self.receive_message()
                
                if response.get('msg_type') == 'msg':
                    # Decrypt response
                    response_msg = ChatMessage(**response)
                    encrypted_response = b64d(response_msg.encrypted_text)
                    decrypted_response = decrypt(encrypted_response, self.aes_key).decode('utf-8')
                    print(f"Server: {decrypted_response}")
                    
                elif response.get('msg_type') == 'error':
                    print(f"Error: {response.get('message')}")
                    
                elif response.get('msg_type') == 'receipt':
                    # Session receipt received
                    receipt = ReceiptMessage(**response)
                    print(f"\n=== Session Receipt ===")
                    print(f"Session ID: {receipt.session_id}")
                    print(f"Transcript Hash: {receipt.transcript_hash}")
                    print(f"Signature: {receipt.signature[:20]}...")
                    break
                    
            except KeyboardInterrupt:
                print("\n\nDisconnecting...")
                break
            except Exception as e:
                print(f"Error: {e}")
                break
    
    def run(self):
        """Run the complete client workflow."""
        try:
            # Connect to server
            if not self.connect():
                return
            
            # Perform handshake
            if not self.handshake():
                return
            
            # Authenticate
            if not self.authenticate():
                print("Authentication failed. Exiting.")
                return
            
            # Start chat
            self.chat_loop()
            
        except Exception as e:
            print(f"Client error: {e}")
        finally:
            self.disconnect()

def main():
    """Main client entry point."""
    print("=== Secure Chat Client ===")
    client = SecureChatClient()
    client.run()

if __name__ == "__main__":
    main()
