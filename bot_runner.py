import sys
import json

def safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    allowed_modules = ['math', 'random', 're', 'json', 'datetime', 'string', 'time', 'requests']
    if name in allowed_modules:
        return __import__(name, globals, locals, fromlist, level)
    raise ImportError(f"Security Policy: Import of module '{name}' is blocked.")

def run():
    try:
        input_data = sys.stdin.read()
        if not input_data:
            return
            
        req = json.loads(input_data)
        code = req.get('code', '')
        event = req.get('event')
        data = req.get('data', {})

        # Setup Sandbox Builtins
        if isinstance(__builtins__, dict):
            safe_builtins = __builtins__.copy()
        else:
            safe_builtins = __builtins__.__dict__.copy()
            
        # Remove dangerous functions
        unsafe_funcs = ['open', 'eval', 'exec', 'compile', 'input', 'memoryview', 'bytearray']
        for k in unsafe_funcs:
            if k in safe_builtins:
                del safe_builtins[k]
                
        # Override import
        safe_builtins['__import__'] = safe_import

        # API Functions injected into the environment
        def send_message(chat_id, content):
            msg = {
                "action": "send_message",
                "chat_id": chat_id,
                "content": str(content)
            }
            print(json.dumps(msg))
            sys.stdout.flush()

        sandbox_env = {
            '__builtins__': safe_builtins,
            'send_message': send_message,
        }

        # Execute the user's bot code
        exec(code, sandbox_env)

        # Dispatch events
        if event == 'message' and 'on_message' in sandbox_env:
            sandbox_env['on_message'](
                data.get('content'), 
                data.get('chatId'), 
                data.get('senderId')
            )

    except Exception as e:
        print(json.dumps({"action": "error", "error": str(e)}))
        sys.stdout.flush()

if __name__ == '__main__':
    run()