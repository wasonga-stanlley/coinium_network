import hashlib
import json
import time
import sqlite3
import random
import string
import logging
from p2pnetworking import start_server, broadcast, PEERS, send_message, add_peer, remove_peer, list_peers, save_peers, load_peers, broadcast_peer_list, ping_peers
import threading
import os


from colorama import Fore, Style, init
init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database setup
conn = sqlite3.connect("blockchain.db", check_same_thread=False)
c = conn.cursor()

P2P_PORT = 5000  # Port for P2P networking
TARGET_VERSION = "1.0.0"
TARGET_NAME = "COINIUM NETWORK"
TARGET_DESCRIPTION = "A decentralized blockchain system with wallet management and transaction processing."
TARGET_AUTHOR = "Stanlley Locke"
TARGET_LICENSE = "MIT License"
TARGET_BLOCKCHAIN_NAME = "COINIUM BLOCKCHAIN"
TARGET_BLOCK_TIME = 60  # seconds
DIFFICULTY_ADJUSTMENT_INTERVAL = 5  # blocks
FEE_PERCENT = 0.01  # 1% transaction fee
MAX_SUPPLY = 21010724  # Total coins in the network
HALVING_INTERVAL = 100  # Blocks after which mining reward is halved
INITIAL_MINING_REWARD = 50  # Initial mining reward for the first block


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

# Burned coins table
c.execute('''
    CREATE TABLE IF NOT EXISTS burned_coins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_address TEXT NOT NULL,
        amount REAL NOT NULL,
        timestamp TEXT NOT NULL
    )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS pending_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        amount REAL NOT NULL,
        timestamp REAL NOT NULL
        )
''')

conn.commit()

# Blockchain setup
blockchain = []
pending_transactions = []
difficulty = 4
#MINING_REWARD = 50  # Reward coins for mining a block

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
    c.execute("SELECT block_index, previous_hash, timestamp, transactions, nonce, hash FROM blockchain ORDER BY block_index ASC")
    rows = c.fetchall()
    for row in rows:
        blockchain.append({
            "block_index": row[0],
            "previous_hash": row[1],
            "timestamp": float(row[2]),
            "transactions": json.loads(row[3]),
            "nonce": row[4],
            "hash": row[5]
        })

c.execute("SELECT sender, recipient, amount, timestamp FROM pending_transactions")
for row in c.fetchall():
    pending_transactions.append({
        "sender": row[0],
        "recipient": row[1],
        "amount": row[2],
        "timestamp": row[3]
    })

def get_total_circulation():
    c.execute("SELECT SUM(balance) FROM wallets")
    total = c.fetchone()[0]
    return total if total is not None else 0.0

def get_current_mining_reward():
    halving_count = (len(blockchain) -1) // HALVING_INTERVAL # -1 to exclude genesis block
    reward = INITIAL_MINING_REWARD / (2 ** halving_count)
    return reward if reward > 0 else 0.01  # Ensure minimum reward of 0.01 coins

def show_suplly():
    total_circulation = get_total_circulation()
    print(Fore.YELLOW+Style.BRIGHT+f"\n💰 Total Circulation in Network: {total_circulation} coins")
    print(Fore.YELLOW+Style.BRIGHT+f"Max Supply: {MAX_SUPPLY} coins\n")
    if total_circulation >= MAX_SUPPLY:
        print(Fore.RED+Style.BRIGHT+"⚠️ Warning: Total circulation has reached the maximum supply limit!\n")
    else:
        print(Fore.GREEN+Style.BRIGHT+"✅ Total circulation is within the supply limit.\n")


# Generate a random wallet address
def generate_wallet_address():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def adjust_difficulty():
    global difficulty
    if len(blockchain) % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 and len(blockchain) > 1:
        actual_time = blockchain[-1]["timestamp"] - blockchain[-DIFFICULTY_ADJUSTMENT_INTERVAL]["timestamp"]
        expected_time = TARGET_BLOCK_TIME * DIFFICULTY_ADJUSTMENT_INTERVAL
        if actual_time < expected_time /2:
            difficulty += 1
            logging.info(f"Difficulty increased to {difficulty}")
            print(Fore.GREEN+Style.BRIGHT+f"\n🔼 Difficulty increased to {difficulty}.\n")
        elif actual_time > expected_time * 2 and difficulty > 1:
            difficulty -= 1
            logging.info(f"Difficulty decreased to {difficulty}")
            print(Fore.RED+Style.BRIGHT+f"\n🔽 Difficulty decreased to {difficulty}.\n")
 
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

def show_liquidity():
    c.execute("SELECT SUM(balance) FROM wallets")
    total = c.fetchone()[0]
    total = total if total is not None else 0.0
    print(Fore.YELLOW+Style.BRIGHT+f"\n💧 Total Liquidity in Network: {total} coins\n")

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

    if sender == recipient:
        print(Fore.RED+Style.BRIGHT+"\n❌ Sender and recipient cannot be the same!\n")
        return

    if amount <= 0:
        if not (amount == 0 and sender == "COINIUM NETWORK" and len(blockchain) == 1 and len(pending_transactions) == 0):

            print(Fore.RED+Style.BRIGHT+"\n❌ Amount must be greater than zero!\n")
            return

        
    # Calculate and net amount
    fee = round(amount * FEE_PERCENT, 8)
    net_amount = amount - fee

    # Check if sender has enough balance including fee
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
        "amount": net_amount,
        "fee": fee,
        "timestamp": time.time()
    }
    
    pending_transactions.append(transaction)
    
    # Update sender & recipient balances in the database
    c.execute("INSERT INTO pending_transactions (sender, recipient, amount, timestamp) VALUES (?, ?, ?, ?)", 
              (sender, recipient, net_amount, transaction["timestamp"]))
    c.execute("UPDATE wallets SET balance = balance - ? WHERE wallet_address = ?", (amount, sender))
    c.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_address = ?", (net_amount, recipient))
    conn.commit()
    
    print(Fore.CYAN+Style.BRIGHT+f"\n✅ Transaction Created! Fee: {fee} coins. Net sent: {net_amount} coins.\n")
    broadcast({"type": "NEW_TRANSACTION", "data": transaction}, use_ssl=False)  # Broadcast transaction to peers


def show_transaction_history(wallet_address):
    c.execute("SELECT sender, recipient, amount, timestamp FROM transactions WHERE sender = ? OR recipient = ? ORDER BY timestamp ASC", (wallet_address, wallet_address)) 
    txs = c.fetchall()
    if not txs:
        print(Fore.YELLOW+Style.BRIGHT+"\n⚠️ No transaction history found for this wallet.\n")      
    else:
        print(Fore.YELLOW+Style.BRIGHT+f"\n🔹 Transaction History for {wallet_address}:")
        for tx in txs:
            if tx[0] == "COINIUM NETWORK" and tx[1] == wallet_address:
                direction = "Mining Reward"
            elif tx[0] == wallet_address:
                direction = "Sent"
            elif tx[1] == wallet_address:
                direction = "Received"
            else:
                direction = "Other"
            print(Fore.LIGHTWHITE_EX+Style.BRIGHT+f"{direction}: {tx[2]} coins | From: {tx[0]} | To: {tx[1]} | Time: {time.ctime(float(tx[3]))}")

# Mining process (Proof-of-Work)
def mine_block():
    #Reload pending transactions from database
    c.execute("SELECT sender, recipient, amount, timestamp FROM pending_transactions")
    pending_transactions.clear()
    for row in c.fetchall():
        pending_transactions.append({
            "sender": row[0],
            "recipient": row[1],
            "amount": row[2],
            "timestamp": row[3]
        })
    if not blockchain:
        print(Fore.RED+Style.BRIGHT+"\n❌ Blockchain is empty! Please create a wallet and make a transaction first.\n")
        return
    if len(blockchain) == 1 and len(pending_transactions) == 0:
        print(Fore.YELLOW+Style.BRIGHT+"\n⚠️ No transactions to mine. Please create a transaction first.\n")
        return

     
    miner_address = input("Enter Miner Wallet Address: ").strip()
    miner_balance = get_wallet_balance(miner_address)
    if miner_balance is None:
        print(Fore.RED+Style.BRIGHT+"\n❌ Miner wallet not found! Please create a wallet first.\n")
        return

    if not pending_transactions:
        print(Fore.YELLOW+Style.BRIGHT+"\n⚠️ No transactions to mine.\n")
        return

    while pending_transactions:
        transaction = pending_transactions.pop(0)

    last_block = blockchain[-1]  
    new_block = {
        "block_index": last_block["block_index"] + 1,
        "previous_hash": last_block["hash"],
        "timestamp": time.time(),
        "transactions": [transaction],
        "nonce": 0
    }

    tx_amount = transaction["amount"]
    percent_reward = tx_amount * 0.1
    fee = transaction.get("fee", 0)
    base_reward = get_current_mining_reward()
    miner_reward = percent_reward + difficulty + fee + base_reward # 10% of transaction amount + difficulty + fee

   
    
    # Add coinbase (reward) transaction
    coinbase_tx = {
        "sender": "COINIUM NETWORK",
        "recipient": miner_address,
        "amount": miner_reward,
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
    broadcast({"type": "NEW_BLOCK", "data": new_block}, use_ssl=False)  # Broadcast new block to peers
    print(Fore.CYAN+Style.BRIGHT+"\n✅ New Block Mined!")
    print(Fore.CYAN+Style.BRIGHT+f"Block Index: {new_block['block_index']}")
    print(Fore.CYAN+Style.BRIGHT+f"Previous Hash: {new_block['previous_hash']}")
    print(Fore.CYAN+Style.BRIGHT+f"Timestamp: {time.ctime(new_block['timestamp'])}")
    print(Fore.CYAN+Style.BRIGHT+f"Transactions: {len(new_block['transactions'])} (including coinbase)")
    print(Fore.CYAN+Style.BRIGHT+f"Nonce: {new_block['nonce']}")
    print(Fore.CYAN+Style.BRIGHT+f"Hash: {new_block['hash']}")
    print(Fore.CYAN+Style.BRIGHT+f"Miner Reward: {miner_reward} coins (10% of transaction amount + difficulty {difficulty} + fee {fee})")
    print(Fore.CYAN+Style.BRIGHT+f"Base Reward: {base_reward} coins (halving every {HALVING_INTERVAL} blocks)")

    # Save block to database (Fixed: Renamed `index` to `block_index`)
    c.execute("INSERT INTO blockchain (block_index, previous_hash, timestamp, transactions, nonce, hash) VALUES (?, ?, ?, ?, ?, ?)", 
              (new_block["block_index"], new_block["previous_hash"], new_block["timestamp"], 
               json.dumps(new_block["transactions"]), new_block["nonce"], new_block["hash"]))
    conn.commit()
    
    for tx in new_block["transactions"]:
        # Save each transaction to the transactions table
        c.execute("INSERT INTO transactions (sender, recipient, amount, timestamp) VALUES (?, ?, ?, ?)", 
                  (tx["sender"], tx["recipient"], tx["amount"], tx["timestamp"]))
        conn.commit()


    # Clear pending transactions
    c.execute("DELETE FROM pending_transactions where sender = ? AND recipient = ? AND amount = ? AND timestamp = ?",
                (transaction["sender"], transaction["recipient"], transaction["amount"], transaction["timestamp"])) 
    conn.commit()
    total_circulation = get_total_circulation()
    if total_circulation + miner_reward > MAX_SUPPLY:
        miner_reward = max(0, MAX_SUPPLY - total_circulation)  # Limit reward to not exceed max supply
        if miner_reward == 0:
            print(Fore.RED+Style.BRIGHT+"\n❌ Mining reward exceeds maximum supply limit! No reward given.\n")
            return
    
    # Update miner's balance with the reward
    c.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_address = ?", (miner_reward, miner_address))
    conn.commit()
    
    print(Fore.GREEN+Style.BRIGHT+f"\n✅ Block Mined for transaction: {tx_amount} coins! Fee: {fee} coins included in reward.")
    print(f"Block Hash: {new_block['hash']}")
    print(f"Miner {miner_address} rewarded with {miner_reward} coins (10% of transaction amount + difficulty {difficulty} + fee {fee}).")
    print(Fore.YELLOW+Style.BRIGHT+f"Current mining reward: {base_reward} coins. Halving every {HALVING_INTERVAL} blocks.")

    adjust_difficulty() 
    print(Fore.GREEN+Style.BRIGHT+f"🔼 Difficulty adjusted. New Difficulty: {difficulty}\n")


def recover_wallet():
    seed_phrase = input(Fore.GREEN+Style.BRIGHT+"Enter Seed Phrase: ").strip()
    private_key = hashlib.sha256(seed_phrase.encode()).hexdigest()
    
    c.execute("SELECT wallet_address, balance FROM wallets WHERE seed_phrase = ?", (seed_phrase,))
    wallet = c.fetchone()
    
    if wallet:
        print(Fore.CYAN+Style.BRIGHT+"\n✅ Wallet Recovered!")
        print(Fore.CYAN+Style.BRIGHT+f"Wallet Address: {wallet[0]}")
        print(Fore.CYAN+Style.BRIGHT+f"Private Key: {private_key}")
        print(Fore.CYAN+Style.BRIGHT+f"Balance: {wallet[1]} coins\n")
        return wallet[0]
    else:
        print(Fore.RED+Style.BRIGHT+"\n❌ Invalid Seed Phrase or Private Key!\n")
        return None

def burn_coins(wallet_address, amount):
    balance = get_wallet_balance(wallet_address)
    if balance is None:
        print(Fore.RED+Style.BRIGHT+"\n❌ Wallet not found!\n")
        return
    if amount <= 0:
        print(Fore.RED+Style.BRIGHT+"\n❌ Amount must be greater than zero!\n")
        return
    if amount > balance:
        print(Fore.RED+Style.BRIGHT+"\n❌ Insufficient balance to burn!\n")
        return
    # Update balance in the database
    c.execute("UPDATE wallets SET balance = balance - ? WHERE wallet_address = ?", (amount, wallet_address))
    #Record the burned coins
    c.execute("INSERT INTO burned_coins (wallet_address, amount, timestamp) VALUES (?, ?, ?)",
                (wallet_address, amount, time.strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    print(Fore.GREEN+Style.BRIGHT+f"\n✅ {amount} coins burned from wallet {wallet_address}.\n")



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
    
def show_mempool():
    c.execute("SELECT sender, recipient, amount, timestamp FROM pending_transactions")
    txs = c.fetchall()
    if not txs:
        print(Fore.YELLOW+Style.BRIGHT+"\n⚠️ Mempool is empty.\n")
    else:
        print(Fore.CYAN+Style.BRIGHT+"\n🔗 Mempool Transactions:")
        for tx in txs:
            print(Fore.LIGHTWHITE_EX+Style.BRIGHT+f"Sender: {tx[0]}, Recipient: {tx[1]}, Amount: {tx[2]} coins, Time: {time.ctime(tx[3])}")


def show_total_burned():
    c.execute("SELECT SUM(amount) FROM burned_coins")
    total_burned = c.fetchone()[0]
    total_burned = total_burned if total_burned is not None else 0.0
    print(Fore.YELLOW+Style.BRIGHT+f"\n🔥 Total Burned Coins: {total_burned} coins\n")

def start_p2p():
    # Start P2P server
    print(Fore.CYAN+Style.BRIGHT+"\nStarting P2P server...")
    threading.Thread(target=start_server, args=(P2P_PORT, blockchain, pending_transactions), daemon=True).start()
    print(Fore.GREEN+Style.BRIGHT+"✅ P2P server started on port "+str(P2P_PORT)+"\n")
    
    # Broadcast initial peer list
    broadcast({"type": "PEER_LIST", "data": list(PEERS)}, use_ssl=False)
    print(Fore.GREEN+Style.BRIGHT+"✅ Initial peer list broadcasted.\n")
    
# Main menu
def main():
    start_p2p()  # Start P2P networking in the background
    print(Fore.GREEN+Style.BRIGHT+"\nWelcome to the Blockchain Interactive CLI!")
    print(Fore.GREEN+Style.BRIGHT+"Version: "+TARGET_VERSION)
    print(Fore.GREEN+Style.BRIGHT+"Name: "+TARGET_NAME)
    print(Fore.GREEN+Style.BRIGHT+"Description: "+TARGET_DESCRIPTION)
    print(Fore.GREEN+Style.BRIGHT+"Author: "+TARGET_AUTHOR)
    print(Fore.GREEN+Style.BRIGHT+"License: "+TARGET_LICENSE)
    print(Fore.GREEN+Style.BRIGHT+"Blockchain Name: "+TARGET_BLOCKCHAIN_NAME)
    print(Fore.GREEN+Style.BRIGHT+"Block Time: "+str(TARGET_BLOCK_TIME)+" seconds")
    print(Fore.GREEN+Style.BRIGHT+"Difficulty: "+str(difficulty))
    print(Fore.GREEN+Style.BRIGHT+"Max Supply: "+str(MAX_SUPPLY)+" coins")
    print(Fore.GREEN+Style.BRIGHT+"Halving Interval: "+str(HALVING_INTERVAL)+" blocks")
    print(Fore.GREEN+Style.BRIGHT+"Initial Mining Reward: "+str(INITIAL_MINING_REWARD)+" coins")
    while True: 
        print(Fore.MAGENTA+Style.BRIGHT+"\nBlockchain Interactive CLI")
        print("1. Create new wallet")
        print("2. List wallets")
        print("3. Create a transaction")
        print("4. Mine pending transactions (Proof-of-Work)")
        print("5. Check wallet balance")
        print("6. Validate blockchain")
        print("7. Show blockchain")
        print("8. Show total liquidity in network")
        print("9. Recover wallet from seed phrase")
        print("10. Show transaction history for a wallet")
        print("11. Show total supply and circulation")
        print("12. Burn coins from a wallet")
        print("13. Show total burned coins")
        print("14. Show Mempool")
        print("15. List Peers")
        print("16. Add Peer")
        print("17. Remove Peer")
        print("18. Broadcast")
        print("19. Send message to peer")
        print("20. Save Peer")
        print("21. Load Peer")
        print("22. Broadcast Peer List")
        print("23. Ping Peers")
        print("24. Exit")
        
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
            show_liquidity()
        elif choice == "9":
            recover_wallet()
        elif choice == "10":
            wallet_address = input(Fore.CYAN+Style.BRIGHT+"Enter wallet address to check History: ").strip()
            show_transaction_history(wallet_address)
        elif choice == "11":
            show_suplly()
        elif choice == "12":
            wallet_address = input(Fore.CYAN+Style.BRIGHT+"Enter wallet address to burn coins: ").strip()
            amount = float(input("Enter amount to burn: "))
            burn_coins(wallet_address, amount)
        elif choice == "13":
            show_total_burned()
        elif choice == "14":
            show_mempool()
        elif choice == "15":
            print(Fore.CYAN+Style.BRIGHT+"\n🔗 Peers in Network:")
            for peer in PEERS:
                print(Fore.LIGHTWHITE_EX+Style.BRIGHT+f"Peer: {peer}")
        elif choice == "16":
            ip = input(Fore.GREEN+Style.BRIGHT+"Enter Peer IP: ").strip()
            port = int(input("Enter Peer Port: ").strip())
            PEERS.add((ip, port))
            print(Fore.GREEN+Style.BRIGHT+f"\n✅ Peer {ip}:{port} added successfully!\n")
        elif choice == "17":
            ip = input(Fore.RED+Style.BRIGHT+"Enter Peer IP to remove: ").strip()
            port = int(input("Enter Peer Port to remove: ").strip())
            if (ip, port) in PEERS:
                PEERS.remove((ip, port))
                print(Fore.GREEN+Style.BRIGHT+f"\n✅ Peer {ip}:{port} removed successfully!\n")
            else:
                print(Fore.RED+Style.BRIGHT+"\n❌ Peer not found!\n")
        elif choice == "18":
            message = input(Fore.CYAN+Style.BRIGHT+"Enter message to broadcast: ").strip()
            broadcast({"type": "BROADCAST", "data": message}, use_ssl=False)
            print(Fore.GREEN+Style.BRIGHT+"\n✅ Message broadcasted to all peers!\n")
        elif choice == "19":
            peer_ip = input(Fore.GREEN+Style.BRIGHT+"Enter Peer IP: ").strip()
            peer_port = int(input("Enter Peer Port: ").strip())
            message = input(Fore.CYAN+Style.BRIGHT+"Enter message to send: ").strip()
            if (peer_ip, peer_port) in PEERS:
                broadcast({"type": "MESSAGE", "data": message}, use_ssl=False)
                print(Fore.GREEN+Style.BRIGHT+"\n✅ Message sent to peer!\n")
            else:
                print(Fore.RED+Style.BRIGHT+"\n❌ Peer not found!\n")
        elif choice == "20":
            filename = input(Fore.GREEN+Style.BRIGHT+"Enter filename to save peers (default: peers.json): ").strip() or "peers.json"
            try:
                with open(filename, 'w') as f:
                    json.dump(list(PEERS), f)
                print(Fore.GREEN+Style.BRIGHT+f"\n✅ Peers saved to {filename} successfully!\n")
            except Exception as e:
                print(Fore.RED+Style.BRIGHT+f"\n❌ Error saving peers: {e}\n")
        elif choice == "21":
            filename = input(Fore.GREEN+Style.BRIGHT+"Enter filename to load peers (default: peers.json): ").strip() or "peers.json"
            try:
                with open(filename, 'r') as f:
                    loaded_peers = json.load(f)
                    PEERS.update(tuple(peer) for peer in loaded_peers)
                print(Fore.GREEN+Style.BRIGHT+f"\n✅ Peers loaded from {filename} successfully!\n")
            except FileNotFoundError:
                print(Fore.RED+Style.BRIGHT+"\n❌ Peers file not found!\n")
            except json.JSONDecodeError:
                print(Fore.RED+Style.BRIGHT+"\n❌ Error decoding peers file!\n")
        elif choice == "22":
            broadcast_peer_list(use_ssl=False)
            print(Fore.GREEN+Style.BRIGHT+"\n✅ Peer list broadcasted to all peers!\n")
        elif choice == "23":
            print(Fore.CYAN+Style.BRIGHT+"\n🔗 Pinging all peers...")
            for peer in PEERS:
                try:
                    response = broadcast({"type": "PING", "data": "Ping"}, use_ssl=False)
                    if response:
                        print(Fore.GREEN+Style.BRIGHT+f"✅ Peer {peer} is online.")
                    else:
                        print(Fore.RED+Style.BRIGHT+f"❌ Peer {peer} is offline.")
                except Exception as e:
                    print(Fore.RED+Style.BRIGHT+f"❌ Error pinging peer {peer}: {e}")
            print(Fore.CYAN+Style.BRIGHT+"🔗 Ping completed.\n")
        elif choice == "24":
            print(Fore.GREEN+Style.BRIGHT+"\n Exiting... Goodbye!\n")
            break1
        else:
            print(Fore.YELLOW+Style.BRIGHT+"\n⚠️ Invalid choice. Try again.\n")

# Run the blockchain system
if __name__ == "__main__":
    main()
