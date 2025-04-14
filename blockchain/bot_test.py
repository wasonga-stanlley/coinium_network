import requests
import time

TOKEN = "7741079240:AAES08fjkZQBv_aH6AZaqFaAg7fyDyijryc"
URL = f"https://api.telegram.org/bot{TOKEN}/"

def get_updates(offset=None):
    response = requests.get(URL + "getUpdates", params={"offset": offset})
    return response.json()["result"]

def send_message(chat_id, text):
    requests.post(URL + "sendMessage", data={"chat_id": chat_id, "text": text})

def main():
    offset = None
    print("Bot is running...")
    while True:
        updates = get_updates(offset)
        for update in updates:
            message = update.get("message")
            if message:
                chat_id = message["chat"]["id"]
                text = message.get("text", "")
                send_message(chat_id, f"You said: {text}")
                offset = update["update_id"] + 1
        time.sleep(1)

if __name__ == "__main__":
    main()
