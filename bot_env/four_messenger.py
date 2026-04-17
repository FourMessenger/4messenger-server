import os
import requests
import traceback

class Bot:
    @staticmethod
    def send_message(chat_id, text):
        server_url = os.environ.get('API_URL') or os.environ.get('SERVER_URL')
        token = os.environ.get('BOT_TOKEN')
        
        if not server_url or not token:
            print("Error: Missing SERVER_URL or BOT_TOKEN. Are you running inside 4 Messenger?")
            return False
            
        print(f"[FOUR_MESSENGER] Sending message to {server_url}/api/chats/{chat_id}/messages")
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        payload = {
            'content': str(text),
            'type': 'text'
        }
        
        try:
            res = requests.post(f"{server_url}/api/chats/{chat_id}/messages", json=payload, headers=headers, timeout=5)
            if res.status_code in [200, 201]:
                print(f"[FOUR_MESSENGER] Message sent successfully to chat {chat_id}")
                return True
            else:
                print(f"[FOUR_MESSENGER] Error sending message: HTTP {res.status_code} - {res.text}")
                return False
        except Exception as e:
            print(f"[FOUR_MESSENGER] Network request failed: {e}")
            return False

    @staticmethod
    def run(handler):
        message = os.environ.get('MESSAGE_TEXT', '')
        chat_id = os.environ.get('CHAT_ID', '')
        sender_id = os.environ.get('SENDER_ID', '')
        
        print(f"[FOUR_MESSENGER] Bot.run triggered. Message: '{message}', Chat: {chat_id}, Sender: {sender_id}")
        
        if chat_id and sender_id:
            try:
                handler(message, chat_id, sender_id)
            except Exception as e:
                print(f"[FOUR_MESSENGER] Exception in user handler:")
                traceback.print_exc()
        else:
            print(f"[FOUR_MESSENGER] Aborting. Missing CHAT_ID or SENDER_ID in env.")

