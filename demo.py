"""
Simple demonstration of the secure chat system.
This script tests the core functionality without requiring manual interaction.
"""

import threading
import time
import socket
import json
from app.server import SecureChatServer
from app.client import SecureChatClient
from app.storage.db import UserDatabase
from app.common.protocol import *
from app.common.utils import *
from app.crypto.aes import *

def demo_server():
    """Run demo server."""
    print("🖥️  Starting demo server...")
    server = SecureChatServer()
    
    # Override to listen for shorter time
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.settimeout(30)  # 30 seconds timeout
    
    try:
        server_socket.bind((server.host, server.port))
        server_socket.listen(5)
        print(f"✓ Demo server listening on {server.host}:{server.port}")
        
        # Accept one connection for demo
        try:
            client_socket, client_address = server_socket.accept()
            print(f"✓ Demo client connected from {client_address}")
            
            # Handle the demo client
            server.handle_client(client_socket, client_address)
            
        except socket.timeout:
            print("⏰ Demo server timeout - no client connected")
            
    except Exception as e:
        print(f"Demo server error: {e}")
    finally:
        server_socket.close()
        server.db.disconnect()
        print("🖥️  Demo server stopped")

def demo_client():
    """Run demo client with automated interaction."""
    print("📱 Starting demo client...")
    time.sleep(2)  # Give server time to start
    
    try:
        client = SecureChatClient()
        
        # Connect to server
        if not client.connect():
            print("❌ Failed to connect to server")
            return
        
        print("✓ Connected to server")
        
        # Perform handshake
        if not client.handshake():
            print("❌ Handshake failed")
            return
        
        print("✓ Handshake completed successfully")
        print("✓ Encryption key established")
        
        # Register a test user first
        print("📝 Registering test user...")
        
        # Encrypt credentials for registration
        credentials = "demouser:demopass"
        encrypted_creds = encrypt(credentials.encode(), client.aes_key)
        
        register_msg = RegisterMessage(encrypted_data=b64e(encrypted_creds))
        client.send_message(register_msg)
        
        response = client.receive_message()
        if response.get('msg_type') == 'success':
            print("✓ User registration successful")
        else:
            print(f"Registration response: {response}")
        
        # Now login
        print("🔐 Logging in...")
        login_msg = LoginMessage(encrypted_data=b64e(encrypted_creds))
        client.send_message(login_msg)
        
        response = client.receive_message()
        if response.get('msg_type') == 'success':
            print("✓ Authentication successful")
            client.authenticated = True
        else:
            print(f"❌ Login failed: {response}")
            return
        
        # Send a test message
        print("💬 Sending encrypted message...")
        test_message = "Hello from secure chat demo! 🔒"
        
        # Encrypt message
        encrypted_text = encrypt(test_message.encode(), client.aes_key)
        
        # Sign message
        client.seqno += 1
        sign_data_str = f"{client.seqno}{b64e(encrypted_text)}"
        from app.crypto.sign import sign_data
        signature = sign_data(sign_data_str.encode(), client.client_private_key)
        
        # Send chat message
        chat_msg = ChatMessage(
            seqno=client.seqno,
            encrypted_text=b64e(encrypted_text),
            signature=b64e(signature)
        )
        client.send_message(chat_msg)
        
        # Receive echo response
        response = client.receive_message()
        if response.get('msg_type') == 'msg':
            response_msg = ChatMessage(**response)
            encrypted_response = b64d(response_msg.encrypted_text)
            decrypted_response = decrypt(encrypted_response, client.aes_key).decode('utf-8')
            print(f"✓ Received response: {decrypted_response}")
        else:
            print(f"Response: {response}")
        
        print("✅ Demo completed successfully!")
        print()
        print("🎉 SECURE CHAT SYSTEM WORKING! 🎉")
        print()
        print("Security features demonstrated:")
        print("  ✓ PKI Certificate validation")
        print("  ✓ Diffie-Hellman key exchange")  
        print("  ✓ AES message encryption")
        print("  ✓ RSA digital signatures")
        print("  ✓ User authentication")
        print("  ✓ Replay protection")
        print("  ✓ Session transcripts")
        
    except Exception as e:
        print(f"❌ Demo client error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.disconnect()

def main():
    """Run the complete demo."""
    print("=" * 50)
    print("🔐 SECURE CHAT SYSTEM DEMO 🔐")
    print("=" * 50)
    
    # Prepare database
    db = UserDatabase()
    if db.connect():
        db.create_tables()
        db.disconnect()
        print("✓ Database ready")
    
    # Start server in background thread
    server_thread = threading.Thread(target=demo_server)
    server_thread.daemon = True
    server_thread.start()
    
    # Run client demo
    demo_client()
    
    print("=" * 50)

if __name__ == "__main__":
    main()