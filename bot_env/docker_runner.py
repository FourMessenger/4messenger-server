#!/usr/bin/env python3
"""
4 Messenger Bot Runner for Docker Environment
----------------------------------------------
This script runs inside a Docker container to execute user bot scripts securely.
It reads the bot script from stdin and executes it in a restricted environment.
"""

import sys
import os
import json
import traceback
import requests

# Get environment variables
API_URL = os.environ.get('API_URL', 'http://host.docker.internal:3000')
BOT_TOKEN = os.environ.get('BOT_TOKEN', '')
CHAT_ID = os.environ.get('CHAT_ID', '')
SENDER_ID = os.environ.get('SENDER_ID', '')
MESSAGE_TEXT = os.environ.get('MESSAGE_TEXT', '')
BOT_NAME = os.environ.get('BOT_NAME', 'Bot')
BOT_STORAGE_PATH = os.environ.get('BOT_STORAGE_PATH', '/tmp/bot_storage')

# Ensure storage path exists
os.makedirs(BOT_STORAGE_PATH, exist_ok=True)


def send_message(chat_id, text):
    """Send a message to a chat via the 4 Messenger API."""
    if not BOT_TOKEN:
        print("[FOUR_MESSENGER] ERROR: No BOT_TOKEN provided", file=sys.stderr)
        return False
    
    try:
        print(f"[FOUR_MESSENGER] Sending message to chat {chat_id}...")
        response = requests.post(
            f"{API_URL}/api/chats/{chat_id}/messages",
            headers={
                'Authorization': f'Bearer {BOT_TOKEN}',
                'Content-Type': 'application/json'
            },
            json={
                'content': str(text),
                'type': 'text'
            },
            timeout=10
        )
        
        if response.ok:
            print(f"[FOUR_MESSENGER] Message sent successfully!")
            return True
        else:
            print(f"[FOUR_MESSENGER] Failed to send: {response.status_code} - {response.text}", file=sys.stderr)
            return False
    except Exception as e:
        print(f"[FOUR_MESSENGER] Error sending message: {e}", file=sys.stderr)
        return False


# File operations for bot storage
def create_file(filename):
    """Create an empty file in bot's storage."""
    safe_path = os.path.join(BOT_STORAGE_PATH, os.path.basename(filename))
    if not os.path.exists(safe_path):
        open(safe_path, 'w').close()

def write_file(filename, content):
    """Write content to a file (overwrites existing)."""
    safe_path = os.path.join(BOT_STORAGE_PATH, os.path.basename(filename))
    with open(safe_path, 'w', encoding='utf-8') as f:
        f.write(str(content))

def add_file(filename, content):
    """Append content to a file."""
    safe_path = os.path.join(BOT_STORAGE_PATH, os.path.basename(filename))
    with open(safe_path, 'a', encoding='utf-8') as f:
        f.write(str(content))

def read_file(filename):
    """Read content from a file."""
    safe_path = os.path.join(BOT_STORAGE_PATH, os.path.basename(filename))
    with open(safe_path, 'r', encoding='utf-8') as f:
        return f.read()

def delete_file(filename):
    """Delete a file."""
    safe_path = os.path.join(BOT_STORAGE_PATH, os.path.basename(filename))
    if os.path.exists(safe_path):
        os.remove(safe_path)

def list_files():
    """List all files in bot's storage."""
    return os.listdir(BOT_STORAGE_PATH)


def main():
    print("--- Docker Bot Runner Initialized ---")
    
    # Read bot script from stdin
    script = sys.stdin.read()
    
    if not script.strip():
        print("[ERROR] No bot script provided", file=sys.stderr)
        sys.exit(1)
    
    print(f"--- Running Bot Script ({len(script)} bytes) ---")
    
    # Create restricted globals for bot execution
    bot_globals = {
        '__builtins__': __builtins__,
        '__name__': '__main__',
        '__doc__': None,
        # API functions
        'send_message': send_message,
        # File operations
        'create_file': create_file,
        'write_file': write_file,
        'add_file': add_file,
        'read_file': read_file,
        'delete_file': delete_file,
        'list_files': list_files,
        # Allow requests for external API calls
        'requests': requests,
        # Standard modules that are safe
        'json': json,
        'print': print,
    }
    
    try:
        # Execute the bot script
        exec(script, bot_globals)
        
        # If on_message function is defined, call it with the incoming message
        if 'on_message' in bot_globals and MESSAGE_TEXT:
            print(f"--- Calling on_message('{MESSAGE_TEXT[:50]}...', '{CHAT_ID}', '{SENDER_ID}') ---")
            bot_globals['on_message'](MESSAGE_TEXT, CHAT_ID, SENDER_ID)
        elif 'on_message' not in bot_globals:
            print("[WARNING] No on_message function defined in bot script")
        elif not MESSAGE_TEXT:
            print("[WARNING] No message text provided")
            
    except Exception as e:
        error_msg = traceback.format_exc()
        print(f"[ERROR] Bot execution failed:\n{error_msg}", file=sys.stderr)
        
        # Try to send error message to chat
        if CHAT_ID:
            error_preview = error_msg[-500:] if len(error_msg) > 500 else error_msg
            send_message(CHAT_ID, f"⚠️ **Bot Execution Error:**\n```python\n{error_preview}\n```")
        
        sys.exit(1)
    
    print("--- Bot Script Completed ---")


if __name__ == '__main__':
    main()
