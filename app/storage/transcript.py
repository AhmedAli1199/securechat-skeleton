"""Append-only transcript + TranscriptHash helpers."""

import os
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Any
from app.common.utils import now_ms, sha256_hex

class TranscriptLogger:
    """Append-only transcript logger for session records."""
    
    def __init__(self, session_id: str, transcript_dir: str = "transcripts"):
        """Initialize transcript logger for a session."""
        self.session_id = session_id
        self.transcript_dir = transcript_dir
        
        # Create transcript directory if it doesn't exist
        os.makedirs(transcript_dir, exist_ok=True)
        
        # Transcript file path
        self.transcript_path = os.path.join(transcript_dir, f"{session_id}.json")
        
        # Initialize empty transcript
        self.transcript = []
        
        # Log session start
        self.log_event("session_start", {"session_id": session_id, "timestamp": now_ms()})
    
    def log_event(self, event_type: str, data: Dict[str, Any]):
        """Log an event to the transcript."""
        entry = {
            "timestamp": now_ms(),
            "event_type": event_type,
            "data": data
        }
        
        self.transcript.append(entry)
        self._save_to_file()
    
    def log_message(self, direction: str, message_type: str, encrypted_content: str, signature: str = None, seqno: int = None):
        """Log a protocol message."""
        data = {
            "direction": direction,  # "client_to_server" or "server_to_client"
            "message_type": message_type,
            "encrypted_content": encrypted_content,
            "seqno": seqno
        }
        
        if signature:
            data["signature"] = signature
        
        self.log_event("protocol_message", data)
    
    def log_authentication(self, username: str, success: bool):
        """Log authentication attempt."""
        self.log_event("authentication", {
            "username": username,
            "success": success
        })
    
    def log_key_exchange(self, phase: str, public_value: str = None):
        """Log key exchange phase."""
        data = {"phase": phase}
        if public_value:
            # Only log hash of public value, not the value itself
            data["public_value_hash"] = sha256_hex(public_value.encode())
        
        self.log_event("key_exchange", data)
    
    def log_error(self, error_code: str, message: str):
        """Log protocol error."""
        self.log_event("protocol_error", {
            "error_code": error_code,
            "message": message
        })
    
    def close_session(self):
        """Close the session and finalize transcript."""
        self.log_event("session_end", {"timestamp": now_ms()})
    
    def _save_to_file(self):
        """Save current transcript to file."""
        try:
            with open(self.transcript_path, 'w') as f:
                json.dump(self.transcript, f, indent=2)
        except Exception as e:
            print(f"Error saving transcript: {e}")
    
    def get_transcript_hash(self) -> str:
        """Calculate SHA-256 hash of the entire transcript."""
        # Convert transcript to canonical JSON string
        transcript_str = json.dumps(self.transcript, sort_keys=True, separators=(',', ':'))
        return sha256_hex(transcript_str.encode())
    
    def get_transcript_content(self) -> List[Dict[str, Any]]:
        """Get the complete transcript."""
        return self.transcript.copy()
    
    def load_from_file(self) -> bool:
        """Load existing transcript from file."""
        try:
            if os.path.exists(self.transcript_path):
                with open(self.transcript_path, 'r') as f:
                    self.transcript = json.load(f)
                return True
        except Exception as e:
            print(f"Error loading transcript: {e}")
        return False

class TranscriptVerifier:
    """Utility for verifying transcript integrity."""
    
    @staticmethod
    def verify_transcript_hash(transcript_path: str, expected_hash: str) -> bool:
        """Verify that a transcript file matches expected hash."""
        try:
            with open(transcript_path, 'r') as f:
                transcript_data = json.load(f)
            
            # Calculate hash
            transcript_str = json.dumps(transcript_data, sort_keys=True, separators=(',', ':'))
            actual_hash = sha256_hex(transcript_str.encode())
            
            return actual_hash == expected_hash
        except Exception as e:
            print(f"Error verifying transcript: {e}")
            return False
    
    @staticmethod
    def get_transcript_summary(transcript_path: str) -> Dict[str, Any]:
        """Get summary information from a transcript."""
        try:
            with open(transcript_path, 'r') as f:
                transcript_data = json.load(f)
            
            if not transcript_data:
                return {"error": "Empty transcript"}
            
            session_start = None
            session_end = None
            message_count = 0
            auth_attempts = 0
            errors = 0
            
            for entry in transcript_data:
                event_type = entry.get("event_type", "")
                
                if event_type == "session_start":
                    session_start = entry.get("timestamp")
                elif event_type == "session_end":
                    session_end = entry.get("timestamp")
                elif event_type == "protocol_message":
                    message_count += 1
                elif event_type == "authentication":
                    auth_attempts += 1
                elif event_type == "protocol_error":
                    errors += 1
            
            return {
                "session_start": session_start,
                "session_end": session_end,
                "total_events": len(transcript_data),
                "message_count": message_count,
                "auth_attempts": auth_attempts,
                "error_count": errors
            }
        except Exception as e:
            return {"error": str(e)}

def list_transcripts(transcript_dir: str = "transcripts") -> List[str]:
    """List all transcript files in directory."""
    try:
        if not os.path.exists(transcript_dir):
            return []
        
        files = []
        for filename in os.listdir(transcript_dir):
            if filename.endswith('.json'):
                files.append(os.path.join(transcript_dir, filename))
        return files
    except Exception as e:
        print(f"Error listing transcripts: {e}")
        return []

def main():
    """Test transcript logging functionality."""
    import uuid
    
    # Generate test session
    session_id = str(uuid.uuid4())
    logger = TranscriptLogger(session_id)
    
    # Test logging
    logger.log_key_exchange("dh_init")
    logger.log_authentication("test_user", True)
    logger.log_message("client_to_server", "msg", "encrypted_content_here", "signature_here", 1)
    logger.close_session()
    
    # Get hash
    transcript_hash = logger.get_transcript_hash()
    print(f"Session {session_id}")
    print(f"Transcript hash: {transcript_hash}")
    
    # Verify
    verifier = TranscriptVerifier()
    verified = verifier.verify_transcript_hash(logger.transcript_path, transcript_hash)
    print(f"Verification: {verified}")
    
    # Summary
    summary = verifier.get_transcript_summary(logger.transcript_path)
    print(f"Summary: {summary}")

if __name__ == "__main__":
    main()
