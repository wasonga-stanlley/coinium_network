#!/usr/bin/env python3
import requests
import time
import hashlib
import json
import sqlite3
import random
import string
import logging
import os

from colorama import Fore, Style, init
init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ----- Telegram Bot Setup -----
TOKEN = "7741079240:AAES08fjkZQBv_aH6AZaqFaAg7fyDyijryc"
URL = f"https://api.telegram.org/bot{TOKEN}/"

def get_updates(offset=None):
    response = requests.get(URL + "getUpdates", params={"offset": offset})
    return response.json()["result"]

def send_message(chat_id, text, reply_markup=None):
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    if reply_markup:
        payload["reply_markup"] = json.dumps(reply_markup)
    requests.post(URL + "sendMessage", data=payload)

def answer_callback(callback_query_id, text=""):
    payload = {"callback_query_id": callback_query_id, "text": text}
    requests.post(URL + "answerCallbackQuery", data=payload)

def send_menu(chat_id):
    keyboard = {
        "inline_keyboard": [
            [
                {"text": "🆕 Create Wallet", "callback_data": "create_wallet"},
                {"text": "📋 List Wallets", "callback_data": "list_wallets"}
            ],
            [
                {"text": "💰 Check Balance", "callback_data": "check_balance"},
                {"text": "🔄 Create Transaction", "callback_data": "create_transaction"}
            ],
            [
                {"text": "⛏️ Mine Block", "callback_data": "mine_block"},
                {"text": "✅ Validate", "callback_data": "validate"}
            ],
            [
                {"text": "📜 Show Chain", "callback_data": "show_chain"},
                {"text": "📝 Pending Tx", "callback_data": "pending_tx"}
            ],
            [
                {"text": "❓ Help", "callback_data": "help"},
                {"text": "ℹ️ About", "callback_data": "about"}
            ]
        ]
    }
    menu_text = "🔘 *Main Menu*:\nSelect an option below:"
    send_message(chat_id, menu_text, reply_markup=keyboard)

# ----- Database and Blockchain Setup -----
conn = sqlite3.connect("blockchain.db", check_same_thread=False)
c = conn.cursor()

# Create wallets table if not exists
c.execute('''
    CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_address TEXT UNIQUE NOT NULL,
        seed_phrase TEXT NOT NULL,
        private_key TEXT NOT NULL,
        balance REAL DEFAULT 0.0
    )
''')
# Create transactions table if not exists
c.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        amount REAL NOT NULL,
        timestamp TEXT
    )
''')
# Create blockchain table if not exists
c.execute('''
    CREATE TABLE IF NOT EXISTS blockchain (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        block_index INTEGER,
        previous_hash TEXT,
        timestamp TEXT,
        transactions TEXT,
        nonce INTEGER,
        hash TEXT
    )
''')
conn.commit()

blockchain = []
pending_transactions = []
difficulty = 4
MINING_REWARD = 50  # Reward coins for mining a block

# Create Genesis Block if not exists in database
c.execute("SELECT COUNT(*) FROM blockchain")
if c.fetchone()[0] == 0:
    genesis_block = {
        "block_index": 0,
        "previous_hash": "0",
        "timestamp": time.time(),
        "transactions": [],
        "nonce": 0,
        "hash": "GENESIS_HASH"
    }
    blockchain.append(genesis_block)
    c.execute(
        "INSERT INTO blockchain (block_index, previous_hash, timestamp, transactions, nonce, hash) VALUES (?, ?, ?, ?, ?, ?)",
        (genesis_block["block_index"], genesis_block["previous_hash"], genesis_block["timestamp"],
         json.dumps(genesis_block["transactions"]), genesis_block["nonce"], genesis_block["hash"])
    )
    conn.commit()
    logging.info(Fore.CYAN + Style.BRIGHT + "✅ Genesis Block Created!")
else:
    c.execute("SELECT block_index, previous_hash, timestamp, transactions, nonce, hash FROM blockchain ORDER BY block_index")
    rows = c.fetchall()
    for row in rows:
        block = {
            "block_index": row[0],
            "previous_hash": row[1],
            "timestamp": row[2],
            "transactions": json.loads(row[3]),
            "nonce": row[4],
            "hash": row[5]
        }
        blockchain.append(block)
    logging.info(Fore.CYAN + Style.BRIGHT + "✅ Genesis Block already exists in the database.")

# ----- Blockchain Core Functions -----
def generate_wallet_address():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def create_wallet_params():
    wallet_address = generate_wallet_address()
    seed_phrase = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    private_key = hashlib.sha256(seed_phrase.encode()).hexdigest()
    
    c.execute("INSERT INTO wallets (wallet_address, seed_phrase, private_key, balance) VALUES (?, ?, ?, ?)", 
              (wallet_address, seed_phrase, private_key, 0.0))
    conn.commit()
    logging.info("New wallet created: %s", wallet_address)
    return {
        "wallet_address": wallet_address,
        "seed_phrase": seed_phrase,
        "private_key": private_key
    }

def list_wallets_info():
    c.execute("SELECT id, wallet_address, balance FROM wallets")
    wallets = c.fetchall()
    if not wallets:
        return "⚠️ *No wallets found!*"
    result = "🔹 *Wallets List:*\n"
    for w in wallets:
        result += f"`ID: {w[0]}` | `{w[1]}` | *Balance:* `{w[2]} coins`\n"
    return result

def get_wallet_balance(wallet_address):
    c.execute("SELECT balance FROM wallets WHERE wallet_address = ?", (wallet_address,))
    wallet = c.fetchone()
    return wallet[0] if wallet else None

def create_transaction_params(sender, recipient, amount):
    sender_balance = get_wallet_balance(sender)
    if sender_balance is None:
        return "❌ *Sender wallet not found!*"
    if sender_balance < amount:
        return "❌ *Insufficient balance in sender wallet!*"
    transaction = {
        "sender": sender,
        "recipient": recipient,
        "amount": amount,
        "timestamp": time.time()
    }
    pending_transactions.append(transaction)
    c.execute("UPDATE wallets SET balance = balance - ? WHERE wallet_address = ?", (amount, sender))
    c.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_address = ?", (amount, recipient))
    conn.commit()
    logging.info("Transaction created: %s -> %s (%s)", sender, recipient, amount)
    return "✅ *Transaction created and added to pending transactions!*"

def mine_block_params(miner_address):
    miner_balance = get_wallet_balance(miner_address)
    if miner_balance is None:
        return "❌ *Miner wallet not found! Please create a wallet first.*"
    if not pending_transactions:
        return "⚠️ *No transactions to mine!*"
    last_block = blockchain[-1]
    new_block = {
        "block_index": last_block["block_index"] + 1,
        "previous_hash": last_block["hash"],
        "timestamp": time.time(),
        "transactions": pending_transactions.copy(),
        "nonce": 0
    }
    coinbase_tx = {
        "sender": "💰 COINIUM NETWORK",
        "recipient": miner_address,
        "amount": MINING_REWARD,
        "timestamp": time.time()
    }
    new_block["transactions"].insert(0, coinbase_tx)
    while True:
        new_block["nonce"] += 1
        block_string = json.dumps(new_block, sort_keys=True).encode()
        block_hash = hashlib.sha256(block_string).hexdigest()
        if block_hash[:difficulty] == "0" * difficulty:
            new_block["hash"] = block_hash
            break
    blockchain.append(new_block)
    c.execute("INSERT INTO blockchain (block_index, previous_hash, timestamp, transactions, nonce, hash) VALUES (?, ?, ?, ?, ?, ?)", 
              (new_block["block_index"], new_block["previous_hash"], new_block["timestamp"], 
               json.dumps(new_block["transactions"]), new_block["nonce"], new_block["hash"]))
    conn.commit()
    pending_transactions.clear()
    c.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_address = ?", (MINING_REWARD, miner_address))
    conn.commit()
    logging.info("Block mined: %s", new_block["hash"])
    return (f"✅ *Block mined successfully!*\n*Block Hash:* `{new_block['hash']}`\n"
            f"🎉 Miner `{miner_address}` rewarded with *{MINING_REWARD} coins*.")

def validate_blockchain_params():
    for i in range(1, len(blockchain)):
        if blockchain[i]["previous_hash"] != blockchain[i-1]["hash"]:
            logging.error("Blockchain invalid at block %s", blockchain[i]["block_index"])
            return False
    return True

def get_blockchain_string():
    if not blockchain:
        return "⚠️ *Blockchain is empty!*"
    result = "🔗 *Blockchain:*\n"
    for block in blockchain:
        result += "```\n" + json.dumps(block, indent=4) + "\n```\n"
    return result

def get_pending_tx_string():
    if not pending_transactions:
        return "📝 *No pending transactions.*"
    result = "📝 *Pending Transactions:*\n"
    for tx in pending_transactions:
        result += f"`From: {tx['sender']}  To: {tx['recipient']}  Amount: {tx['amount']}`\n"
    return result

# ----- Telegram Bot Main Loop -----
def main():
    offset = None
    logging.info("🤖 Bot is running...")
    while True:
        updates = get_updates(offset)
        for update in updates:
            if "message" in update:
                chat_id = update["message"]["chat"]["id"]
                text = update["message"].get("text", "")
                args = text.split()
                command = args[0].lower()
                
                if command == "/start":
                    welcome_text = (
                        "👋 *Welcome to the Blockchain Bot!*\n\n"
                        "Use the menu buttons below to interact with the system."
                    )
                    send_message(chat_id, welcome_text)
                    send_menu(chat_id)
                
                elif command == "/balance":
                    if len(args) < 2:
                        send_message(chat_id, "⚠️ *Usage:* `/balance <wallet_address>`")
                    else:
                        wallet_address = args[1]
                        balance = get_wallet_balance(wallet_address)
                        if balance is None:
                            send_message(chat_id, "❌ *Wallet not found!*")
                        else:
                            send_message(chat_id, f"💰 *Balance for* `{wallet_address}`: *{balance} coins*")
                        send_menu(chat_id)
                
                elif command == "/transaction":
                    # Expected format: /transaction <sender> <recipient> <amount>
                    if len(args) < 4:
                        send_message(chat_id, "⚠️ *Usage:* `/transaction <sender> <recipient> <amount>`")
                    else:
                        sender = args[1]
                        recipient = args[2]
                        try:
                            amount = float(args[3])
                        except ValueError:
                            send_message(chat_id, "❌ *Amount must be a number!*")
                            continue
                        response = create_transaction_params(sender, recipient, amount)
                        send_message(chat_id, response)
                        send_menu(chat_id)
                
                elif command == "/mine":
                    if len(args) < 2:
                        send_message(chat_id, "⚠️ *Usage:* `/mine <miner_address>`")
                    else:
                        miner_address = args[1]
                        response = mine_block_params(miner_address)
                        send_message(chat_id, response)
                        send_menu(chat_id)
                
                else:
                    # For unknown or text messages, simply show the menu
                    send_menu(chat_id)
                
                offset = update["update_id"] + 1

            elif "callback_query" in update:
                callback = update["callback_query"]
                data = callback["data"]
                chat_id = callback["message"]["chat"]["id"]
                callback_id = callback["id"]

                if data == "create_wallet":
                    wallet_info = create_wallet_params()
                    response = (f"✅ *New Wallet Created!*\n"
                                f"*Address:* `{wallet_info['wallet_address']}`\n"
                                f"*Seed Phrase:* `{wallet_info['seed_phrase']}`\n"
                                f"*Private Key:* `{wallet_info['private_key']}`")
                    send_message(chat_id, response)
                elif data == "list_wallets":
                    response = list_wallets_info()
                    send_message(chat_id, response)
                elif data == "check_balance":
                    response = "💡 *To check balance, type:* `/balance <wallet_address>`"
                    send_message(chat_id, response)
                elif data == "create_transaction":
                    response = "💡 *To create a transaction, type:* `/transaction <sender> <recipient> <amount>`"
                    send_message(chat_id, response)
                elif data == "mine_block":
                    response = "💡 *To mine a block, type:* `/mine <miner_address>`"
                    send_message(chat_id, response)
                elif data == "validate":
                    is_valid = validate_blockchain_params()
                    response = "✅ *Blockchain is VALID.*" if is_valid else "❌ *Blockchain is INVALID!*"
                    send_message(chat_id, response)
                elif data == "show_chain":
                    response = get_blockchain_string()
                    send_message(chat_id, response)
                elif data == "pending_tx":
                    response = get_pending_tx_string()
                    send_message(chat_id, response)
                elif data == "help":
                    response = (
                        "❓ *Help:*\n"
                        "Use the buttons or type commands as follows:\n\n"
                        "• `/createwallet` - Create a new wallet\n"
                        "• `/listwallets` - List all wallets\n"
                        "• `/balance <wallet_address>` - Check wallet balance\n"
                        "• `/transaction <sender> <recipient> <amount>` - Create a transaction\n"
                        "• `/mine <miner_address>` - Mine pending transactions\n"
                        "• `/validate` - Validate the blockchain\n"
                        "• `/showchain` - Show the blockchain\n"
                        "• `/pendingtx` - Show pending transactions"
                    )
                    send_message(chat_id, response)
                elif data == "about":
                    response = (
                        "ℹ️ *About:*\n"
                        "This Blockchain Bot integrates a simple blockchain network with wallet, transaction, and mining functionality.\n"
                        "Developed with Python and SQLite."
                    )
                    send_message(chat_id, response)
                else:
                    send_message(chat_id, "❓ *Unknown option!*")
                
                answer_callback(callback_id)
                send_menu(chat_id)
                offset = update["update_id"] + 1
        time.sleep(1)

if __name__ == "__main__":
    main()
