import sys
import builtins
import os

# Secure Sandbox setup
# Block dangerous modules from being imported
blocked_modules = ['subprocess', 'shutil', 'pty', 'commands']

# Replace dangerous functions from os with secure wrappers instead of deleting them, 
# to avoid breaking standard libraries (like 'requests'/'tempfile') that expect them to exist.
dangerous_os_funcs = ['system', 'popen', 'spawn', 'spawnl', 'spawnle', 'spawnv', 'spawnve', 'execl', 'execle', 'execlp', 'execv', 'execve', 'execvp', 'fork', 'kill']

def secure_os_block(*args, **kwargs):
    raise PermissionError("This OS function is disabled for security reasons.")

for func in dangerous_os_funcs:
    if hasattr(os, func):
        setattr(os, func, secure_os_block)

# Protect filesystem manipulation functions (allow internal libraries, block direct bot calls)
filesystem_funcs = ['remove', 'unlink', 'rmdir', 'mkdir', 'rename', 'replace', 'chmod', 'chown']
for func_name in filesystem_funcs:
    if hasattr(os, func_name):
        original_func = getattr(os, func_name)
        def make_secure_fs_func(orig_func):
            def secure_fs_func(*args, **kwargs):
                try:
                    frame = sys._getframe(1)
                    if frame.f_code.co_filename == '<string>':
                        raise PermissionError(f"Filesystem function '{orig_func.__name__}' is blocked for bots.")
                except ValueError:
                    pass
                return orig_func(*args, **kwargs)
            return secure_fs_func
        setattr(os, func_name, make_secure_fs_func(original_func))

# Prevent file creation / writing
original_open = builtins.open
def secure_open(*args, **kwargs):
    mode = args[1] if len(args) > 1 else kwargs.get('mode', 'r')
    if any(c in mode for c in ['w', 'a', '+', 'x']):
        try:
            frame = sys._getframe(1)
            if frame.f_code.co_filename == '<string>':
                raise PermissionError("Write access is blocked for bots.")
        except ValueError:
            pass
    return original_open(*args, **kwargs)
builtins.open = secure_open

# Prevent importing unapproved modules directly in the bot script (Allowlist approach)
original_import = builtins.__import__
def secure_import(name, globals=None, locals=None, fromlist=(), level=0):
    allowed_direct_modules = [
        'requests', 'math', 'random', 'json', 'datetime', 're', 
        'string', 'time', 'urllib', 'collections', 'itertools', 'hashlib'
    ]
    
    try:
        frame = sys._getframe(1)
        if frame.f_code.co_filename == '<string>':
            base_module = name.split('.')[0]
            if base_module not in allowed_direct_modules:
                raise ImportError(f"Security Policy: Module '{name}' is not in the allowed list. Allowed modules: {', '.join(allowed_direct_modules)}")
    except ValueError:
        pass
            
    return original_import(name, globals, locals, fromlist, level)
builtins.__import__ = secure_import

# Also disable direct access to importlib to prevent workarounds
try:
    import importlib
    original_import_module = importlib.import_module
    def secure_import_module(name, package=None):
        try:
            frame = sys._getframe(1)
            if frame.f_code.co_filename == '<string>':
                base_module = name.split('.')[0]
                if base_module not in ['requests', 'math', 'random', 'json', 'datetime', 're', 'string', 'time', 'urllib', 'collections', 'itertools', 'hashlib']:
                    raise ImportError(f"Security Policy: Module '{name}' is not allowed via importlib.")
        except ValueError:
            pass
        return original_import_module(name, package)
    importlib.import_module = secure_import_module
except ImportError:
    pass

# Ensure 'four_messenger' can be imported by adding the directory to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Start memory monitoring if enabled
import threading
import time
MAX_MEMORY_MB = int(os.environ.get('MAX_MEMORY_MB', '50'))
try:
    import tracemalloc
    tracemalloc.start()
    def memory_monitor():
        while True:
            time.sleep(0.5)
            current, _ = tracemalloc.get_traced_memory()
            if current > MAX_MEMORY_MB * 1024 * 1024:
                err_msg = f"Memory Limit Exceeded: Bot used {current/1024/1024:.2f} MB (Limit: {MAX_MEMORY_MB} MB)"
                print(f"Bot Execution Error: {err_msg}", file=sys.stderr)
                cid = os.environ.get('CHAT_ID')
                if cid and 'send_message' in globals():
                    try:
                        send_message(cid, f"⚠️ **Bot Error:**\n{err_msg}")
                    except: pass
                os._exit(1)
    
    monitor_thread = threading.Thread(target=memory_monitor, daemon=True)
    monitor_thread.start()
except ImportError:
    pass

# Read the bot's script from standard input
script = sys.stdin.read()

# DON'T replace escaped characters here - JSON parsing should handle this
# Replacing \n would break string literals like "\n\n" in Python code

import traceback

# Define the built-in send_message function
import requests

def send_message(chat_id, text):
    server_url = os.environ.get('API_URL')
    token = os.environ.get('BOT_TOKEN')
    
    if not server_url or not token:
        print("Error: Missing API_URL or BOT_TOKEN.")
        return False
        
    print(f"[FOUR_MESSENGER] Sending message to chat {chat_id}...")
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    payload = {'content': str(text), 'type': 'text'}
    
    try:
        res = requests.post(f"{server_url}/api/chats/{chat_id}/messages", json=payload, headers=headers, timeout=5)
        if res.status_code in [200, 201]:
            print(f"[FOUR_MESSENGER] Message sent successfully!")
            return True
        else:
            print(f"[FOUR_MESSENGER] HTTP {res.status_code}: {res.text}")
            return False
    except Exception as e:
        print(f"[FOUR_MESSENGER] Network Error: {e}")
        return False

# --- SAFE FILE I/O FOR BOTS ---
BOT_NAME = os.environ.get('BOT_NAME')
if BOT_NAME:
    server_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bot_dir = os.path.abspath(os.path.join(server_root, "bot_files", BOT_NAME))
    
    if not os.path.exists(bot_dir):
        os.makedirs(bot_dir, exist_ok=True)

    def _resolve_bot_path(filename):
        target_path = os.path.abspath(os.path.join(bot_dir, filename))
        if not target_path.startswith(bot_dir):
            raise PermissionError(f"Access denied: Cannot access files outside your bot directory.")
        return target_path

    def bot_write_file(filename, content):
        path = _resolve_bot_path(filename)
        with original_open(path, 'w', encoding='utf-8') as f:
            f.write(str(content))
        return True

    def bot_read_file(filename):
        path = _resolve_bot_path(filename)
        if not os.path.exists(path):
            raise FileNotFoundError(f"File '{filename}' not found.")
        with original_open(path, 'r', encoding='utf-8') as f:
            return f.read()

    def bot_add_file(filename, content):
        path = _resolve_bot_path(filename)
        with original_open(path, 'a', encoding='utf-8') as f:
            f.write(str(content))
        return True

    def bot_create_file(filename):
        path = _resolve_bot_path(filename)
        with original_open(path, 'a', encoding='utf-8') as f:
            pass
        return True

    def bot_delete_file(filename):
        path = _resolve_bot_path(filename)
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    def bot_list_files():
        return os.listdir(bot_dir)
else:
    def _disabled(*args, **kwargs):
        raise PermissionError("File operations are disabled because BOT_NAME is not set.")
    bot_write_file = bot_read_file = bot_add_file = bot_delete_file = bot_list_files = bot_create_file = _disabled

# Setup execution globals
bot_globals = {
    '__name__': '__main__', 
    '__builtins__': builtins,
    'send_message': send_message,
    'create_file': bot_create_file,
    'write_file': bot_write_file,
    'read_file': bot_read_file,
    'add_file': bot_add_file,
    'delete_file': bot_delete_file,
    'list_files': bot_list_files
}

# Execute the script
try:
    print(f"--- Sandbox Initialized, Running Script ---")
    exec(script, bot_globals)
    
    # Automatically call on_message if defined
    if 'on_message' in bot_globals:
        msg = os.environ.get('MESSAGE_TEXT', '')
        cid = os.environ.get('CHAT_ID', '')
        sid = os.environ.get('SENDER_ID', '')
        bot_globals['on_message'](msg, cid, sid)
        
except Exception as e:
    import traceback
    err_str = traceback.format_exc()
    print(f"Bot Execution Error: {e}", file=sys.stderr)
    print(err_str, file=sys.stderr)
    
    # Send crash report to chat
    cid = os.environ.get('CHAT_ID')
    if cid:
        send_message(cid, f"⚠️ **Bot Execution Error:**\n```python\n{err_str}\n```")
