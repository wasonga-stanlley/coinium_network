import hashlib
import json
import time
import sqlite3
import random
import string
import logging

from colorama import Fore, Style, init
init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database setup
conn = sqlite3.connect("blockchain.db", check_same_thread=False)
c = conn.cursor()

# Ensure wallets table exists
c.execute('''
    CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_address TEXT UNIQUE NOT NULL,
        seed_phrase TEXT NOT NULL,
        private_key TEXT NOT NULL,
        balance REAL DEFAULT 0.0
    )
''')

# Ensure transactions table exists
c.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        amount REAL NOT NULL,
        timestamp TEXT
    )
''')

# Ensure blockchain table exists (Fixed: Renamed `index` to `block_index`)
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

# Blockchain setup
blockchain = []
pending_transactions = []
difficulty = 4
MINING_REWARD = 50  # Reward coins for mining a block

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
    print(Fore.CYAN+Style.BRIGHT+"✅ Genesis Block Created!")
else:
    # Optionally, load existing blockchain entries into memory.
    print(Fore.CYAN+Style.BRIGHT+"✅ Genesis Block already exists in the database. ")

# Generate a random wallet address
def generate_wallet_address():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

# Create new wallet
def create_wallet():
    wallet_address = generate_wallet_address()
    seed_phrase = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    private_key = hashlib.sha256(seed_phrase.encode()).hexdigest()
    
    c.execute("INSERT INTO wallets (wallet_address, seed_phrase, private_key, balance) VALUES (?, ?, ?, ?)", 
              (wallet_address, seed_phrase, private_key, 0.0))
    conn.commit()
    
    print(Fore.CYAN+Style.BRIGHT+"\n✅ New Wallet Created!")
    print(Fore.CYAN+Style.BRIGHT+f"Wallet Address: {wallet_address}")
    print(Fore.CYAN+Style.BRIGHT+f"Seed Phrase: {seed_phrase}")
    print(Fore.CYAN+Style.BRIGHT+f"Private Key: {private_key}\n")
    return wallet_address

# List all wallets
def list_wallets():
    c.execute("SELECT id, wallet_address, balance FROM wallets")
    wallets = c.fetchall()
    
    if not wallets:
        print(Fore.YELLOW+Style.BRIGHT+"\n⚠️ No wallets found.\n")
    else:
        print(Fore.YELLOW+Style.BRIGHT+"\n🔹 Wallets:")
        for w in wallets:
            print(Fore.LIGHTWHITE_EX+Style.BRIGHT+f"ID: {w[0]}, Address: {w[1]}, Balance: {w[2]}")

# Get balance of a wallet
def get_wallet_balance(wallet_address):
    c.execute("SELECT balance FROM wallets WHERE wallet_address = ?", (wallet_address,))
    wallet = c.fetchone()
    return wallet[0] if wallet else None

# Create a new transaction
def create_transaction():
    sender = input(Fore.GREEN+Style.BRIGHT+"Sender Wallet Address: ")
    recipient = input(Fore.BLUE+Style.BRIGHT+"Recipient Wallet Address: ")
    amount = float(input("Amount: "))

    # Check if sender has enough balance
    sender_balance = get_wallet_balance(sender)
    if sender_balance is None:
        print(Fore.RED+Style.BRIGHT+"\n❌ Sender wallet not found!\n")
        return
    if sender_balance < amount:
        print(Fore.RED+Style.BRIGHT+"\n❌ Insufficient balance!\n")
        return
    
    transaction = {
        "sender": sender,
        "recipient": recipient,
        "amount": amount,
        "timestamp": time.time()
    }
    
    pending_transactions.append(transaction)
    
    # Update sender & recipient balances in the database
    c.execute("UPDATE wallets SET balance = balance - ? WHERE wallet_address = ?", (amount, sender))
    c.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_address = ?", (amount, recipient))
    conn.commit()
    
    print(Fore.CYAN+Style.BRIGHT+"\n✅ Transaction Created & Added to Pending Transactions!\n")

# Mining process (Proof-of-Work)
def mine_block():
    miner_address = input("Enter Miner Wallet Address: ").strip()
    miner_balance = get_wallet_balance(miner_address)
    if miner_balance is None:
        print(Fore.RED+Style.BRIGHT+"\n❌ Miner wallet not found! Please create a wallet first.\n")
        return

    if not pending_transactions:
        print(Fore.YELLOW+Style.BRIGHT+"\n⚠️ No transactions to mine.\n")
        return

    last_block = blockchain[-1]  # Get the last block (Genesis Block if nothing else)
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
    new_block["transactions"].insert(0, coinbase_tx)  # add reward tx at beginning

    # Proof-of-Work
    while True:
        new_block["nonce"] += 1
        block_string = json.dumps(new_block, sort_keys=True).encode()
        block_hash = hashlib.sha256(block_string).hexdigest()
        if block_hash[:difficulty] == "0" * difficulty:
            new_block["hash"] = block_hash
            break
    
    # Save block in blockchain (in-memory)
    blockchain.append(new_block)

    # Save block to database (Fixed: Renamed `index` to `block_index`)
    c.execute("INSERT INTO blockchain (block_index, previous_hash, timestamp, transactions, nonce, hash) VALUES (?, ?, ?, ?, ?, ?)", 
              (new_block["block_index"], new_block["previous_hash"], new_block["timestamp"], 
               json.dumps(new_block["transactions"]), new_block["nonce"], new_block["hash"]))
    conn.commit()
    
    # Clear pending transactions
    pending_transactions.clear()
    
    # Update miner's balance with the reward
    c.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_address = ?", (MINING_REWARD, miner_address))
    conn.commit()
    
    print(Fore.GREEN+Style.BRIGHT+"\n✅ Block Mined Successfully!")
    print(f"Block Hash: {new_block['hash']}")
    print(f"Miner {miner_address} rewarded with {MINING_REWARD} coins.\n")

# Validate blockchain
def validate_blockchain():
    for i in range(1, len(blockchain)):
        prev_block = blockchain[i - 1]
        curr_block = blockchain[i]
        if curr_block["previous_hash"] != prev_block["hash"]:
            print(Fore.RED+Style.BRIGHT+"\n❌ Blockchain is INVALID!\n")
            return False
    print(Fore.GREEN+Style.BRIGHT+"\n✅ Blockchain is VALID!\n")
    return True

# Show entire blockchain
def show_blockchain():
    if not blockchain:
        print(Fore.YELLOW+Style.BRIGHT+"\n⚠️ Blockchain is empty.\n")
    else:
        print(Fore.CYAN+Style.BRIGHT+"\n🔗 Blockchain:")
        for block in blockchain:
            print(json.dumps(block, indent=4))

# Main menu
def main():
    while True:
        print(Fore.MAGENTA+Style.BRIGHT+"\nBlockchain Interactive CLI")
        print("1. Create new wallet")
        print("2. List wallets")
        print("3. Create a transaction")
        print("4. Mine pending transactions (Proof-of-Work)")
        print("5. Check wallet balance")
        print("6. Validate blockchain")
        print("7. Show blockchain")
        print("8. Exit")
        
        choice = input(Fore.CYAN+Style.BRIGHT+"Enter your choice: ").strip()
        
        if choice == "1":
            create_wallet()
        elif choice == "2":
            list_wallets()
        elif choice == "3":
            create_transaction()
        elif choice == "4":
            mine_block()
        elif choice == "5":
            wallet_address = input(Fore.CYAN+Style.BRIGHT+"Enter wallet address: ").strip()
            balance = get_wallet_balance(wallet_address)
            if balance is None:
                print(Fore.RED+Style.BRIGHT+"\n❌ Wallet not found!\n")
            else:
                print(Fore.YELLOW+Style.BRIGHT+f"\n💰 Wallet Balance: {balance} coins\n")
        elif choice == "6":
            validate_blockchain()
        elif choice == "7":
            show_blockchain()
        elif choice == "8":
            print(Fore.GREEN+Style.BRIGHT+"\n Exiting... Goodbye!\n")
            break
        else:
            print(Fore.YELLOW+Style.BRIGHT+"\n⚠️ Invalid choice. Try again.\n")

# Run the blockchain system
if __name__ == "__main__":
    main()
