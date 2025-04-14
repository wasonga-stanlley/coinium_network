from flask import Flask, render_template, request, jsonify
import hashlib
import json
import time
import sqlite3
import random
import string

app = Flask(__name__)

# Database setup
conn = sqlite3.connect("blockchain.db", check_same_thread=False)
c = conn.cursor()

# Create tables if they don't exist

c.execute('''
    CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_address TEXT UNIQUE NOT NULL,
        seed_phrase TEXT NOT NULL,
        private_key TEXT NOT NULL,
        balance REAL DEFAULT 0.0
    )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        amount REAL NOT NULL,
        timestamp TEXT
    )
''')

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

# Global blockchain and pending transactions list
blockchain = []
pending_transactions = []
difficulty = 4
MINING_REWARD = 50  # Reward for mining a block

# Create the Genesis Block if blockchain table is empty
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
else:
    # Optionally, load blockchain entries from database into memory.
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

# Utility functions
def generate_wallet_address():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def create_wallet():
    wallet_address = generate_wallet_address()
    seed_phrase = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    private_key = hashlib.sha256(seed_phrase.encode()).hexdigest()
    c.execute("INSERT INTO wallets (wallet_address, seed_phrase, private_key, balance) VALUES (?, ?, ?, ?)", 
              (wallet_address, seed_phrase, private_key, 0.0))
    conn.commit()
    return {
        "wallet_address": wallet_address,
        "seed_phrase": seed_phrase,
        "private_key": private_key
    }

def list_wallets():
    c.execute("SELECT id, wallet_address, balance FROM wallets")
    wallets = c.fetchall()
    return [{"id": w[0], "wallet_address": w[1], "balance": w[2]} for w in wallets]

def get_wallet_balance(wallet_address):
    c.execute("SELECT balance FROM wallets WHERE wallet_address = ?", (wallet_address,))
    wallet = c.fetchone()
    return wallet[0] if wallet else None

def create_transaction(sender, recipient, amount):
    sender_balance = get_wallet_balance(sender)
    if sender_balance is None:
        return {"error": "Sender wallet not found!"}
    if sender_balance < amount:
        return {"error": "Insufficient balance!"}
    
    transaction = {
        "sender": sender,
        "recipient": recipient,
        "amount": amount,
        "timestamp": time.time()
    }
    
    pending_transactions.append(transaction)
    
    # Update balances in the database
    c.execute("UPDATE wallets SET balance = balance - ? WHERE wallet_address = ?", (amount, sender))
    c.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_address = ?", (amount, recipient))
    conn.commit()
    
    return {"message": "Transaction created and added to pending transactions."}

def mine_block(miner_address):
    miner_balance = get_wallet_balance(miner_address)
    if miner_balance is None:
        return {"error": "Miner wallet not found!"}
    if not pending_transactions:
        return {"error": "No transactions to mine."}
    
    last_block = blockchain[-1]
    new_block = {
        "block_index": last_block["block_index"] + 1,
        "previous_hash": last_block["hash"],
        "timestamp": time.time(),
        "transactions": pending_transactions.copy(),
        "nonce": 0
    }
    
    # Add coinbase (reward) transaction
    coinbase_tx = {
        "sender": "COINIUM NETWORK",
        "recipient": miner_address,
        "amount": MINING_REWARD,
        "timestamp": time.time()
    }
    new_block["transactions"].insert(0, coinbase_tx)
    
    # Proof-of-Work
    while True:
        new_block["nonce"] += 1
        block_string = json.dumps(new_block, sort_keys=True).encode()
        block_hash = hashlib.sha256(block_string).hexdigest()
        if block_hash[:difficulty] == "0" * difficulty:
            new_block["hash"] = block_hash
            break

    blockchain.append(new_block)

    # Save new block to the database
    c.execute("INSERT INTO blockchain (block_index, previous_hash, timestamp, transactions, nonce, hash) VALUES (?, ?, ?, ?, ?, ?)", 
              (new_block["block_index"], new_block["previous_hash"], new_block["timestamp"], 
               json.dumps(new_block["transactions"]), new_block["nonce"], new_block["hash"]))
    conn.commit()
    
    pending_transactions.clear()
    
    # Update miner's balance with the reward
    c.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_address = ?", (MINING_REWARD, miner_address))
    conn.commit()
    
    return {"message": "Block mined successfully!", "block_hash": new_block["hash"], "reward": MINING_REWARD}

def validate_blockchain():
    for i in range(1, len(blockchain)):
        prev_block = blockchain[i - 1]
        curr_block = blockchain[i]
        if curr_block["previous_hash"] != prev_block["hash"]:
            return {"valid": False, "message": "Blockchain is INVALID!"}
    return {"valid": True, "message": "Blockchain is VALID!"}

def show_blockchain():
    return blockchain

# Flask routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/create_wallet", methods=["POST"])
def route_create_wallet():
    wallet = create_wallet()
    return jsonify(wallet)

@app.route("/list_wallets", methods=["GET"])
def route_list_wallets():
    wallets = list_wallets()
    return jsonify(wallets)

@app.route("/create_transaction", methods=["POST"])
def route_create_transaction():
    data = request.json
    sender = data.get("sender")
    recipient = data.get("recipient")
    amount = float(data.get("amount", 0))
    result = create_transaction(sender, recipient, amount)
    return jsonify(result)

@app.route("/mine_block", methods=["POST"])
def route_mine_block():
    data = request.json
    miner_address = data.get("miner_address")
    result = mine_block(miner_address)
    return jsonify(result)

@app.route("/wallet_balance", methods=["GET"])
def route_wallet_balance():
    wallet_address = request.args.get("wallet_address")
    balance = get_wallet_balance(wallet_address)
    if balance is None:
        return jsonify({"error": "Wallet not found!"})
    return jsonify({"wallet_address": wallet_address, "balance": balance})

@app.route("/validate_blockchain", methods=["GET"])
def route_validate_blockchain():
    result = validate_blockchain()
    return jsonify(result)

@app.route("/show_blockchain", methods=["GET"])
def route_show_blockchain():
    chain = show_blockchain()
    return jsonify(chain)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
