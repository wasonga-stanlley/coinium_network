import hashlib
import json
import time
import sqlite3
import random
import string
import logging
import threading
import os
import requests
from colorama import Fore, Style, init
from p2pnetworking2 import (
    start_server, broadcast, PEERS, send_message, add_peer, remove_peer,
    list_peers, save_peers, load_peers, broadcast_peer_list, ping_peers,
    setup_nat_traversal, generate_ssl_cert, get_validators
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

import base64


# Initialize colorama
init(autoreset=True)

# Enhanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
    handlers=[
        logging.FileHandler("blockchain.log"),
        logging.StreamHandler()
    ]
)

# ============== CONFIGURATION ==============
P2P_PORT = 5000
RPC_PORT = 5001
TARGET_VERSION = "3.0.0"
TARGET_NAME = "COINIUM BLOCKCHAIN PRO"
TARGET_DESCRIPTION = "Advanced blockchain with smart contracts, privacy features, and governance"
TARGET_AUTHOR = "Stanlley Locke"
TARGET_LICENSE = "MIT License"
TARGET_BLOCKCHAIN_NAME = "COINIUM BLOCKCHAIN"
TARGET_BLOCK_TIME = 60  # seconds
DIFFICULTY_ADJUSTMENT_INTERVAL = 2016  # Bitcoin-style interval
FEE_PERCENT = 0.01  # 1% transaction fee
MAX_SUPPLY = 21010724  # Total coins
HALVING_INTERVAL = 100  # Blocks
INITIAL_MINING_REWARD = 50
SHARD_COUNT = 4  # Number of shards
DIFFICULTY = 4  # Initial difficulty
MIN_STAKE = 1000  # Minimum coins to stake

# ============== DATABASE SETUP ==============
db_lock = threading.Lock()
conn = sqlite3.connect("blockchain.db", check_same_thread=False)
c = conn.cursor()

# Create tables with enhanced schema
c.execute('''
    CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_address TEXT UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        encrypted_private_key TEXT NOT NULL,
        seed_phrase TEXT NOT NULL,
        balance REAL DEFAULT 0.0,
        staked REAL DEFAULT 0.0,
        last_online REAL DEFAULT 0.0
    )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tx_hash TEXT UNIQUE NOT NULL,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        amount REAL NOT NULL,
        fee REAL NOT NULL DEFAULT 0,
        timestamp REAL NOT NULL,
        signature TEXT,
        is_coinbase INTEGER DEFAULT 0,
        shard_id INTEGER
    )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        block_index INTEGER UNIQUE NOT NULL,
        previous_hash TEXT NOT NULL,
        timestamp REAL NOT NULL,
        merkle_root TEXT NOT NULL,
        nonce INTEGER NOT NULL,
        hash TEXT UNIQUE NOT NULL,
        difficulty INTEGER NOT NULL,
        validator TEXT,
        vote_count INTEGER DEFAULT 0
    )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS utxos (
        tx_id TEXT NOT NULL,
        output_index INTEGER NOT NULL,
        recipient TEXT NOT NULL,
        amount REAL NOT NULL,
        spent INTEGER DEFAULT 0,
        PRIMARY KEY (tx_id, output_index)
    )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS contracts (
        address TEXT PRIMARY KEY,
        code TEXT NOT NULL,
        creator TEXT NOT NULL,
        balance REAL DEFAULT 0.0,
        storage TEXT
    )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS nfts (
        id TEXT PRIMARY KEY,
        creator TEXT NOT NULL,
        owner TEXT NOT NULL,
        metadata_uri TEXT NOT NULL,
        created_at REAL NOT NULL
    )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS proposals (
        id TEXT PRIMARY KEY,
        creator TEXT NOT NULL,
        description TEXT NOT NULL,
        options TEXT NOT NULL,  -- JSON array
        votes TEXT NOT NULL,    -- JSON object {option: amount}
        start_time REAL NOT NULL,
        end_time REAL NOT NULL,
        executed INTEGER DEFAULT 0
    )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS payment_channels (
        id TEXT PRIMARY KEY,
        party1 TEXT NOT NULL,
        party2 TEXT NOT NULL,
        deposit1 REAL NOT NULL,
        deposit2 REAL NOT NULL,
        balance1 REAL NOT NULL,
        balance2 REAL NOT NULL,
        state_version INTEGER DEFAULT 0,
        closing_tx_id TEXT,
        closed INTEGER DEFAULT 0
    )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS burned_coins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_address TEXT NOT NULL,
        amount REAL NOT NULL,
        timestamp REAL NOT NULL
    )
''')


conn.commit()
get_validators()

# ============== GLOBAL STATE ==============
blockchain = []
pending_transactions = []
difficulty = DIFFICULTY
contract_vm = None
shard_id = random.randint(0, SHARD_COUNT - 1)  # Each node assigned to a shard

# Initialize blockchain
c.execute("SELECT COUNT(*) FROM blocks")
if c.fetchone()[0] == 0:
    genesis_block = {
        "block_index": 0,
        "previous_hash": "0",
        "timestamp": time.time(),
        "transactions": [],
        "merkle_root": "0",
        "nonce": 0,
        "hash": "GENESIS_HASH",
        "difficulty": difficulty,
        "validator": "NETWORK"
    }
    blockchain.append(genesis_block)
    c.execute(
        "INSERT INTO blocks (block_index, previous_hash, timestamp, merkle_root, nonce, hash, difficulty) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (genesis_block["block_index"], genesis_block["previous_hash"], genesis_block["timestamp"],
         genesis_block["merkle_root"], genesis_block["nonce"], genesis_block["hash"], difficulty)
    )
    conn.commit()
    logging.info("Genesis Block Created")
else:
    c.execute("SELECT block_index, previous_hash, timestamp, merkle_root, nonce, hash, difficulty, validator FROM blocks ORDER BY block_index ASC")
    blockchain = [{
        "block_index": row[0],
        "previous_hash": row[1],
        "timestamp": row[2],
        "merkle_root": row[3],
        "nonce": row[4],
        "hash": row[5],
        "difficulty": row[6],
        "validator": row[7]
    } for row in c.fetchall()]
    logging.info(f"Loaded blockchain with {len(blockchain)} blocks")

# ============== CRYPTO FUNCTIONS ==============
def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_private_key(private_key_hex, password, salt):
    private_bytes = bytes.fromhex(private_key_hex)


    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(private_bytes) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

def decrypt_private_key(encrypted_data, password, salt):
    data = base64.b64decode(encrypted_data)
    iv, tag, ciphertext = data[:12], data[12:28], data[28:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    private_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    return serialization.load_pem_private_key(
        private_bytes,
        password=None,
        backend=default_backend()
    )

def sign_data(private_key, data):
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    return private_key.sign(
        data.encode(),
        ec.ECDSA(hashes.SHA256())
    ).hex()

def verify_signature(public_key, data, signature):
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    try:
        public_key.verify(
            bytes.fromhex(signature),
            data.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False

def public_key_to_address(public_key):
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return hashlib.sha256(pub_bytes).hexdigest()

# ============== WALLET MANAGEMENT ==============
def create_wallet(password):
    private_key, public_key = generate_key_pair()
    wallet_address = public_key_to_address(public_key)
    seed_phrase = ''.join(random.choices(string.ascii_letters + string.digits, k=24))


    priv_bytes = private_key.private_bytes( 
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    
    encrypted_pk = encrypt_private_key(priv_bytes.hex(), password, seed_phrase)


    c.execute(
        "INSERT INTO wallets (wallet_address, public_key, encrypted_private_key, seed_phrase, balance) "
        "VALUES (?, ?, ?, ?, ?)", 
        (wallet_address, pub_bytes.hex(), encrypted_pk, seed_phrase, 0.0)
    )
    conn.commit()
    return {
        "address": wallet_address,
        "seed_phrase": seed_phrase,
        "public_key": pub_bytes.hex()
    }

def recover_wallet(seed_phrase, password):
    c.execute("SELECT wallet_address, encrypted_private_key FROM wallets WHERE seed_phrase = ?", (seed_phrase,))
    wallet = c.fetchone()
    if not wallet:
        return None
    
    address, encrypted_pk = wallet
    try:
        private_key = decrypt_private_key(encrypted_pk, password, seed_phrase)
        return address
    except:
        return None

def get_wallet_balance(wallet_address):
    c.execute("SELECT balance FROM wallets WHERE wallet_address = ?", (wallet_address,))
    result = c.fetchone()
    return result[0] if result else 0.0

def stake_coins(wallet_address, amount):
    balance = get_wallet_balance(wallet_address)
    if balance < amount:
        return False
    
    c.execute("UPDATE wallets SET balance = balance - ?, staked = staked + ? WHERE wallet_address = ?", 
              (amount, amount, wallet_address))
    conn.commit()
    return True

def unstake_coins(wallet_address, amount):
    c.execute("SELECT staked FROM wallets WHERE wallet_address = ?", (wallet_address,))
    staked = c.fetchone()[0]
    if staked < amount:
        return False
    
    c.execute("UPDATE wallets SET balance = balance + ?, staked = staked - ? WHERE wallet_address = ?", 
              (amount, amount, wallet_address))
    conn.commit()
    return True

# ============== TRANSACTION SYSTEM ==============
def create_transaction(sender, sender_private_key, recipient, amount):
    # Calculate fees
    fee = amount * FEE_PERCENT
    net_amount = amount - fee
    
    # Create transaction
    tx = {
        "sender": sender,
        "recipient": recipient,
        "amount": net_amount,
        "fee": fee,
        "timestamp": time.time(),
        "shard": get_shard(recipient)
    }
    
    # Sign transaction
    tx["signature"] = sign_data(sender_private_key, tx)
    
    # Add to pending transactions
    pending_transactions.append(tx)
    broadcast({"type": "NEW_TRANSACTION", "data": tx})
    
    return tx

def validate_transaction(tx):
    # Basic validation
    if tx["amount"] <= 0:
        return False
        
    # Signature verification
    c.execute("SELECT public_key FROM wallets WHERE wallet_address = ?", (tx["sender"],))
    result = c.fetchone()
    if not result:
        return False
    
    public_key = serialization.load_der_public_key(
        bytes.fromhex(result[0]),
        backend=default_backend()
    )
    tx_copy = tx.copy()
    signature = tx_copy.pop("signature")
    return verify_signature(public_key, tx_copy, signature)

# ============== BLOCKCHAIN OPERATIONS ==============
def mine_block():

    global pending_transactions

    #Prompt miners adress
    validator_address = input("\nEnter your wallet address to mine and receive rewards: ").strip()
  
    if not validate_validator(validator_address):
        logging.error("Invalid validator address")
        print(Fore.RED + Style.BRIGHT +f"\n❌ You must stake at least {MIN_STAKE} coins to be a validator")
        return None


    last_block = blockchain[-1]
    #transactions = [tx for tx in pending_transactions if get_shard(tx["recipient"]) == shard_id][:100]
    transactions = pending_transactions[:100]

    if not transactions:
        print(Fore.YELLOW + Style.BRIGHT + "\n⚠️ No transactions available to mine")
        return None
    
    # Create coinbase transaction
    base_reward = get_current_mining_reward()
    total_fees = sum(tx['fee'] for tx in transactions)
    difficulty_bonus = difficulty * 0.5
    
    total_reward = base_reward + total_fees + difficulty_bonus
    coinbase_tx = {
        "sender": "COINIUM NETWORK",
        "recipient": validator_address,
        "amount": total_reward,
        "fee": 0,
        "timestamp": time.time(),
        "shard": shard_id,
        "is_coinbase": True
    }
    transactions.insert(0, coinbase_tx)
    
    # Create block
    new_block = {
        "block_index": last_block["block_index"] + 1,
        "previous_hash": last_block["hash"],
        "timestamp": time.time(),
        "transactions": transactions,
        "merkle_root": calculate_merkle_root(transactions),
        "nonce": 0,
        "difficulty": difficulty,
        "validator": validator_address
    }
    
    # Proof of Work
    while True:
        block_string = json.dumps(new_block, sort_keys=True).encode()
        new_block["hash"] = hashlib.sha256(block_string).hexdigest()
        
        if new_block["hash"].startswith("0" * difficulty):
            break
        
        new_block["nonce"] += 1
        if new_block["nonce"] > 1000000:
            print(Fore.RED + Style.BRIGHT + "\n❌ Mining failed, try again later")
            return None

    new_block["hash"] = calculate_block_hash(new_block)

    # Add to blockchain
    blockchain.append(new_block)
    broadcast({"type": "NEW_BLOCK", "data": new_block})
    
    # Update database
    c.execute(
        "INSERT INTO blocks (block_index, previous_hash, timestamp, merkle_root, nonce, hash, difficulty, validator) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (new_block["block_index"], new_block["previous_hash"], new_block["timestamp"],
         new_block["merkle_root"], new_block["nonce"], new_block["hash"], new_block["difficulty"], new_block["validator"])
    )
    
    # Process transactions
    for tx in transactions:
        tx_hash = hashlib.sha256(json.dumps(tx).encode()).hexdigest()
        c.execute(
            "INSERT INTO transactions (tx_hash, sender, recipient, amount, fee, timestamp, signature, is_coinbase, shard_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tx_hash, tx["sender"], tx["recipient"], 
             tx["amount"], tx["fee"], tx["timestamp"], tx.get("signature", ""), 
             int(tx.get("is_coinbase", False)), tx.get("shard", shard_id))
        )
        
        # Update balances (simplified)
        if not tx.get("is_coinbase", False):
            c.execute("UPDATE wallets SET balance = balance - ? WHERE wallet_address = ?", 
                      (tx["amount"] + tx["fee"], tx["sender"]))
        c.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_address = ?", 
                  (tx["amount"], tx["recipient"]))
    c.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_address = ?",
              (total_reward, validator_address))    

    conn.commit()
    
    # Clear processed transactions
    pending_transactions = [tx for tx in pending_transactions if tx not in transactions]
    
    # Adjust difficulty
    adjust_difficulty()
    
    #Finish mining
    print(Fore.GREEN + Style.BRIGHT + f"\n✅ Block mined successfully!")
    print(f"Block Hash: {new_block['hash'][:16]}...")
    print(f"Transactions: {len(transactions)}")
    print(f"Validator Reward: {total_reward} coins")
    print(f"  • Base Reward: {base_reward}")
    print(f"  • Transaction Fees: {total_fees}")
    print(f"  • Difficulty Bonus: {difficulty_bonus}")

    return new_block

def calculate_merkle_root(transactions):
    if not transactions:
        return "0"
    
    tx_hashes = [hashlib.sha256(json.dumps(tx).encode()).hexdigest() for tx in transactions]
    
    while len(tx_hashes) > 1:
        if len(tx_hashes) % 2 != 0:
            tx_hashes.append(tx_hashes[-1])
        new_hashes = []
        for i in range(0, len(tx_hashes), 2):
            combined = tx_hashes[i] + tx_hashes[i+1]
            new_hash = hashlib.sha256(combined.encode()).hexdigest()
            new_hashes.append(new_hash)
        tx_hashes = new_hashes
    
    return tx_hashes[0]

def calculate_block_hash(block):
    block_string = json.dumps({
        "index": block["block_index"],
        "previous_hash": block["previous_hash"],
        "timestamp": block["timestamp"],
        "merkle_root": block["merkle_root"],
        "difficulty": block["difficulty"],
        "validator": block["validator"]
    }, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()

def validate_block(block):
    # Validate block structure
    required_fields = ["block_index", "previous_hash", "timestamp", "merkle_root", "hash", "difficulty"]
    if not all(field in block for field in required_fields):
        return False
    
    # Validate hash
    if calculate_block_hash(block) != block["hash"]:
        return False
    
    # Validate transactions
    for tx in block.get("transactions", []):
        if not validate_transaction(tx):
            return False
    
    return True

def adjust_difficulty():
    global difficulty
    if len(blockchain) % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 and len(blockchain) > 1:
        start_index = max(0, len(blockchain) - DIFFICULTY_ADJUSTMENT_INTERVAL)
        start_block = blockchain[start_index]
        end_block = blockchain[-1]
        
        actual_time = end_block["timestamp"] - start_block["timestamp"]
        expected_time = TARGET_BLOCK_TIME * DIFFICULTY_ADJUSTMENT_INTERVAL
        
        # Calculate new difficulty
        difficulty = max(1, int(difficulty * (expected_time / actual_time)))
        logging.info(f"Difficulty adjusted to {difficulty}")

def get_current_mining_reward():
    halving_count = max(0, (len(blockchain) - 1) // HALVING_INTERVAL)
    return INITIAL_MINING_REWARD / (2 ** halving_count)

def validate_blockchain():
    if not blockchain:
        return False
    
    for i in range(1, len(blockchain)):
        block = blockchain[i]
        previous_block = blockchain[i - 1]
        
        # Validate previous hash
        if block["previous_hash"] != previous_block["hash"]:
            logging.error(f"Block {block['block_index']} has invalid previous hash")
            return False

        # Validate block hash
        computed_hash = calculate_block_hash(block)
        if computed_hash != block["hash"]:
            logging.error(f"Block {block['block_index']} has invalid hash: {computed_hash} != {block['hash']}")
            return False
        
        # Validate block structure
        if not validate_block(block):
            logging.error(f"Block {block['block_index']} is invalid")
            return False
    
    logging.info("Blockchain is valid")
    return True

# ============== CONSENSUS MECHANISMS ==============
def select_validator():
    c.execute("SELECT wallet_address, staked FROM wallets WHERE staked >= ?", (MIN_STAKE,))
    validators = c.fetchall()
    if not validators:
        return None
    
    total_stake = sum(stake for _, stake in validators)
    selection_point = random.uniform(0, total_stake)
    current = 0
    
    for address, stake in validators:
        current += stake
        if current >= selection_point:
            return address
    
    return validators[-1][0]

def validate_validator(validator_address):
    c.execute("SELECT staked FROM wallets WHERE wallet_address = ?", (validator_address,))
    result = c.fetchone()
    return result and result[0] >= MIN_STAKE

# ============== NETWORK ENHANCEMENTS ==============
def get_shard(wallet_address):
    return int(wallet_address, 16) % SHARD_COUNT

def handle_cross_shard_transaction(tx):
    return get_shard(tx["sender"]) != get_shard(tx["recipient"])

# ============== SMART CONTRACTS ==============
class ContractVM:
    def __init__(self):
        self.contracts = {}
    
    def deploy_contract(self, code, creator, initial_fund=0):
        contract_address = hashlib.sha256(code.encode() + creator.encode()).hexdigest()
        self.contracts[contract_address] = {
            "code": code,
            "storage": {},
            "balance": initial_fund
        }
        
        # Save to database
        c.execute(
            "INSERT INTO contracts (address, code, creator, balance, storage) "
            "VALUES (?, ?, ?, ?, ?)",
            (contract_address, code, creator, initial_fund, json.dumps({}))
        )
        conn.commit()
        return contract_address
    
    def execute_contract(self, contract_address, function, args, caller, value=0):
        contract = self.contracts.get(contract_address)
        if not contract:
            return None
        
        # Simple stack-based VM
        stack = []
        instructions = contract["code"].split()
        
        for instruction in instructions:
            if instruction.isdigit():
                stack.append(int(instruction))
            elif instruction == "ADD":
                a = stack.pop()
                b = stack.pop()
                stack.append(a + b)
            elif instruction == "STORE":
                key = stack.pop()
                value = stack.pop()
                contract["storage"][str(key)] = value
            elif instruction == "LOAD":
                key = stack.pop()
                stack.append(contract["storage"].get(str(key), 0))
        
        # Update database
        c.execute(
            "UPDATE contracts SET storage = ?, balance = balance + ? WHERE address = ?",
            (json.dumps(contract["storage"]), value, contract_address)
        )
        conn.commit()
        
        return stack[-1] if stack else 0

# ============== NFT SYSTEM ==============
def create_nft(creator, metadata_uri):
    nft_id = hashlib.sha256(f"{creator}{metadata_uri}{time.time()}".encode()).hexdigest()
    c.execute(
        "INSERT INTO nfts (id, creator, owner, metadata_uri, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (nft_id, creator, creator, metadata_uri, time.time())
    )
    conn.commit()
    return nft_id

def transfer_nft(nft_id, sender, recipient, sender_private_key):
    c.execute("SELECT owner FROM nfts WHERE id = ?", (nft_id,))
    result = c.fetchone()
    if not result or result[0] != sender:
        return False
    
    # Create transfer transaction
    transfer_tx = {
        "nft_id": nft_id,
        "from": sender,
        "to": recipient,
        "timestamp": time.time()
    }
    signature = sign_data(sender_private_key, transfer_tx)
    
    # Update ownership
    c.execute(
        "UPDATE nfts SET owner = ? WHERE id = ?",
        (recipient, nft_id)
    )
    conn.commit()
    
    # Broadcast transfer
    broadcast({
        "type": "NFT_TRANSFER",
        "data": {
            "tx": transfer_tx,
            "signature": signature
        }
    })
    return True

# ============== PAYMENT CHANNELS ==============
def open_payment_channel(party1, party2, amount1, amount2):
    channel_id = hashlib.sha256(f"{party1}{party2}{time.time()}".encode()).hexdigest()
    c.execute(
        "INSERT INTO payment_channels (id, party1, party2, deposit1, deposit2, balance1, balance2) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (channel_id, party1, party2, amount1, amount2, amount1, amount2)
    )
    conn.commit()
    
    # Lock funds
    c.execute("UPDATE wallets SET balance = balance - ? WHERE wallet_address = ?", (amount1, party1))
    c.execute("UPDATE wallets SET balance = balance - ? WHERE wallet_address = ?", (amount2, party2))
    conn.commit()
    
    return channel_id

def update_payment_channel(channel_id, new_balance1, new_balance2, signature1, signature2):
    c.execute(
        "SELECT party1, party2, balance1, balance2 FROM payment_channels WHERE id = ?",
        (channel_id,)
    )
    channel = c.fetchone()
    if not channel:
        return False
    
    party1, party2, balance1, balance2 = channel
    total = balance1 + balance2
    if new_balance1 + new_balance2 != total:
        return False
    
    # Verify signatures
    update_data = {
        "channel_id": channel_id,
        "balance1": new_balance1,
        "balance2": new_balance2,
        "version": c.execute("SELECT state_version FROM payment_channels WHERE id = ?", (channel_id,)).fetchone()[0] + 1
    }
    
    if not verify_signature(party1, update_data, signature1) or \
       not verify_signature(party2, update_data, signature2):
        return False
    
    # Update channel state
    c.execute(
        "UPDATE payment_channels SET balance1 = ?, balance2 = ?, state_version = ? WHERE id = ?",
        (new_balance1, new_balance2, update_data["version"], channel_id))
    conn.commit()
    return True

def close_payment_channel(channel_id, closing_signature):
    c.execute(
        "SELECT party1, party2, balance1, balance2 FROM payment_channels WHERE id = ? AND closed = 0",
        (channel_id,)
    )
    channel = c.fetchone()
    if not channel:
        return False
    
    party1, party2, balance1, balance2 = channel
    
    # Verify signature
    if not verify_signature(party1, {"channel_id": channel_id, "action": "close"}, closing_signature):
        return False
    
    # Create settlement transactions
    create_transaction("CHANNEL", None, party1, balance1)
    create_transaction("CHANNEL", None, party2, balance2)
    
    # Mark channel as closed
    c.execute(
        "UPDATE payment_channels SET closed = 1 WHERE id = ?",
        (channel_id,)
    )
    conn.commit()
    return True

# ============== GOVERNANCE SYSTEM ==============
def create_proposal(creator, description, options):
    proposal_id = hashlib.sha256(f"{creator}{description}{time.time()}".encode()).hexdigest()
    c.execute(
        "INSERT INTO proposals (id, creator, description, options, votes, start_time, end_time) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (proposal_id, creator, description, json.dumps(options), json.dumps({}), time.time(), time.time() + 604800)
    )
    conn.commit()
    return proposal_id

def vote_on_proposal(proposal_id, voter, option, stake_amount):
    c.execute(
        "SELECT options, end_time FROM proposals WHERE id = ? AND executed = 0",
        (proposal_id,)
    )
    proposal = c.fetchone()
    if not proposal or time.time() > proposal[1]:
        return False
    
    options = json.loads(proposal[0])
    if option not in options:
        return False
    
    # Stake tokens to vote
    if not stake_coins(voter, stake_amount):
        return False
    
    # Update votes
    c.execute("SELECT votes FROM proposals WHERE id = ?", (proposal_id,))
    votes = json.loads(c.fetchone()[0])
    votes[option] = votes.get(option, 0) + stake_amount
    
    c.execute(
        "UPDATE proposals SET votes = ? WHERE id = ?",
        (json.dumps(votes), proposal_id))
    conn.commit()
    return True

def execute_proposal(proposal_id):
    c.execute(
        "SELECT options, votes, end_time FROM proposals WHERE id = ? AND executed = 0",
        (proposal_id,)
    )
    proposal = c.fetchone()
    if not proposal or time.time() < proposal[2]:
        return False
    
    options = json.loads(proposal[0])
    votes = json.loads(proposal[1])
    
    # Find winning option
    winning_option = max(votes, key=votes.get)
    
    # Execute proposal (simplified)
    logging.info(f"Executing proposal {proposal_id}: {winning_option}")
    
    # Mark as executed
    c.execute(
        "UPDATE proposals SET executed = 1 WHERE id = ?",
        (proposal_id,)
    )
    conn.commit()
    return True

# ============== UTILITY FUNCTIONS ==============
def get_total_circulation():
    c.execute("SELECT SUM(balance) FROM wallets")
    total = c.fetchone()[0]
    return total if total is not None else 0.0

def get_total_burned():
    c.execute("SELECT SUM(amount) FROM burned_coins")
    total = c.fetchone()[0]
    return total if total is not None else 0.0

def show_supply():
    total_circulation = get_total_circulation()
    total_burned = get_total_burned()
    print(Fore.YELLOW + Style.BRIGHT + f"\n💰 Total Circulation: {total_circulation} coins")
    print(Fore.RED + Style.BRIGHT + f"🔥 Total Burned: {total_burned} coins")
    print(Fore.CYAN + Style.BRIGHT + f"💎 Max Supply: {MAX_SUPPLY} coins")
    
    if total_circulation >= MAX_SUPPLY:
        print(Fore.RED + Style.BRIGHT + "⚠️ Warning: Total circulation has reached the maximum supply limit!")
    else:
        print(Fore.GREEN + Style.BRIGHT + "✅ Total circulation is within the supply limit.")

def show_liquidity():
    c.execute("SELECT SUM(balance) FROM wallets")
    total = c.fetchone()[0] or 0.0
    print(Fore.YELLOW + Style.BRIGHT + f"\n💧 Total Liquidity: {total} coins")

def show_transaction_history(wallet_address):
    c.execute("SELECT sender, recipient, amount, timestamp FROM transactions WHERE sender = ? OR recipient = ? ORDER BY timestamp DESC", 
              (wallet_address, wallet_address))
    txs = c.fetchall()
    
    if not txs:
        print(Fore.YELLOW + Style.BRIGHT + "\n⚠️ No transaction history found")
        return
        
    print(Fore.CYAN + Style.BRIGHT + f"\n📜 Transaction History for {wallet_address}:")
    for tx in txs:
        direction = "Sent" if tx[0] == wallet_address else "Received"
        counterparty = tx[1] if direction == "Sent" else tx[0]
        print(f"{direction} {tx[2]} coins to {counterparty} at {time.ctime(tx[3])}")

def show_mempool():
    if not pending_transactions:
        print(Fore.YELLOW + Style.BRIGHT + "\n⚠️ Mempool is empty")
        return
        
    print(Fore.CYAN + Style.BRIGHT + "\n📦 Mempool Transactions:")
    for tx in pending_transactions:
        print(f"{tx['sender']} -> {tx['recipient']}: {tx['amount']} coins")

def show_blockchain_summary():
    print(Fore.CYAN + Style.BRIGHT + "\n🔗 Blockchain Summary:")
    print(f"Height: {len(blockchain)} blocks")
    print(f"Difficulty: {difficulty}")
    print(f"Pending Transactions: {len(pending_transactions)}")
    
    c.execute("SELECT block_index, hash FROM blocks ORDER BY block_index DESC LIMIT 5")
    print("\nLast 5 Blocks:")
    for block in c.fetchall():
        print(f"Block {block[0]}: {block[1][:16]}...")

def burn_coins(wallet_address, amount):
    balance = get_wallet_balance(wallet_address)
    if balance < amount:
        print(Fore.RED + Style.BRIGHT + "\n❌ Insufficient balance!")
        return False
        
    c.execute("UPDATE wallets SET balance = balance - ? WHERE wallet_address = ?", (amount, wallet_address))
    c.execute("INSERT INTO burned_coins (wallet_address, amount, timestamp) VALUES (?, ?, ?)",
              (wallet_address, amount, time.time()))
    conn.commit()
    print(Fore.GREEN + Style.BRIGHT + f"\n✅ Burned {amount} coins from wallet {wallet_address}")
    return True

def fund_wallet(wallet_address, amount):
    c.execute("SELECT balance FROM wallets WHERE wallet_address = ?", (wallet_address,))
    if c.fetchone():
        c.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_address = ?", (amount, wallet_address))
        conn.commit()
        print(Fore.GREEN + Style.BRIGHT + f"\n✅ Funded {amount} coins to wallet {wallet_address}")
    
    else:
        print(Fore.RED + Style.BRIGHT + "\n❌ Wallet not found!")
    

        

# ============== CLI MENUS ==============
def wallet_menu():
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + "\n👛 WALLET MENU")
        print("1. Create new wallet")
        print("2. List wallets")
        print("3. Recover wallet")
        print("4. Check balance")
        print("5. Transaction history")
        print("6. Fund Wallet")
        print("7. Back to main")
        
        choice = input(Fore.CYAN + Style.BRIGHT + "Enter choice: ").strip()
        
        if choice == "1":
            password = input("Set wallet password: ")
            wallet = create_wallet(password)
            print(Fore.GREEN + Style.BRIGHT + f"\n✅ Wallet created: {wallet['address']}")
            print(f"Seed phrase: {wallet['seed_phrase']}")
            
        elif choice == "2":
            c.execute("SELECT wallet_address, balance FROM wallets")
            wallets = c.fetchall()
            if not wallets:
                print(Fore.YELLOW + Style.BRIGHT + "\n⚠️ No wallets found")
            else:
                print(Fore.CYAN + Style.BRIGHT + "\n📋 Wallets:")
                for i, wallet in enumerate(wallets):
                    print(f"{i+1}. {wallet[0]} - Balance: {wallet[1]} coins")
                    
        elif choice == "3":
            seed_phrase = input("Enter seed phrase: ")
            password = input("Enter password: ")
            address = recover_wallet(seed_phrase, password)
            if address:
                print(Fore.GREEN + Style.BRIGHT + f"\n✅ Wallet recovered: {address}")
            else:
                print(Fore.RED + Style.BRIGHT + "\n❌ Recovery failed")
                
        elif choice == "4":
            address = input("Enter wallet address: ")
            balance = get_wallet_balance(address)
            if balance is None:
                print(Fore.RED + Style.BRIGHT + "\n❌ Wallet not found")
            else:
                print(Fore.GREEN + Style.BRIGHT + f"\n💰 Balance: {balance} coins")
                
        elif choice == "5":
            address = input("Enter wallet address: ")
            show_transaction_history(address)

        elif choice == "6":
            address = input("Enter wallet address: ")
            amount = float(input("Enter amount to fund: "))
            fund_wallet(address, amount)
            
        elif choice == "7":
            return
            
        else:
            print(Fore.RED + Style.BRIGHT + "\n❌ Invalid choice")

def transaction_menu():
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + "\n💸 TRANSACTION MENU")
        print("1. Create transaction")
        print("2. View mempool")
        print("3. Back to main")
        
        choice = input(Fore.CYAN + Style.BRIGHT + "Enter choice: ").strip()
        
        if choice == "1":
            sender = input("Your address: ")
            password = input("Wallet password: ")
            recipient = input("Recipient address: ")
            amount = float(input("Amount: "))
            
            # Recover private key
            c.execute("SELECT seed_phrase, encrypted_private_key FROM wallets WHERE wallet_address = ?", (sender,))
            result = c.fetchone()
            if not result:
                print(Fore.RED + Style.BRIGHT + "\n❌ Wallet not found")
                continue
                
            seed, enc_pk = result
            try:
                private_key = decrypt_private_key(enc_pk, password, seed)
                tx = create_transaction(sender, private_key, recipient, amount)
                print(Fore.GREEN + Style.BRIGHT + f"\n✅ Transaction created: {hashlib.sha256(json.dumps(tx).encode()).hexdigest()}")
            except:
                print(Fore.RED + Style.BRIGHT + "\n❌ Invalid password")
                
        elif choice == "2":
            show_mempool()
            
        elif choice == "3":
            return
            
        else:
            print(Fore.RED + Style.BRIGHT + "\n❌ Invalid choice")

def block_menu():
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + "\n⛏️ BLOCK MENU")
        print("1. Mine block")
        print("2. Blockchain summary")
        print("3. Validate blockchain")
        print("4. Back to main")
        
        choice = input(Fore.CYAN + Style.BRIGHT + "Enter choice: ").strip()
        
        if choice == "1":
            block = mine_block()
            if not block:
                print(Fore.RED + Style.BRIGHT + "\n❌ Mining failed")
                
        elif choice == "2":
            show_blockchain_summary()
            
        elif choice == "3":
            if validate_blockchain():
                print(Fore.GREEN + Style.BRIGHT + "\n✅ Blockchain is valid!")
            else:
                print(Fore.RED + Style.BRIGHT + "\n❌ Blockchain validation failed!")
                
        elif choice == "4":
            return
            
        else:
            print(Fore.RED + Style.BRIGHT + "\n❌ Invalid choice")

def mining_command():
    while True:
        block = mine_block()
        if not block:
            print(Fore.RED + Style.BRIGHT + "\n❌ Mining failed, retrying...")
            time.sleep(5)
        else:
            print(Fore.GREEN + Style.BRIGHT + f"\n✅ Block mined successfully! Hash: {block['hash'][:16]}...")
            break


def network_menu():
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + "\n🌐 NETWORK MENU")
        print("1. List peers")
        print("2. Add peer")
        print("3. Remove peer")
        print("4. Ping peers")
        print("5. Broadcast peer list")
        print("6. Save peers")
        print("7. Load peers")
        print("8. Network metrics")
        print("9. Back to main")
        
        choice = input(Fore.CYAN + Style.BRIGHT + "Enter choice: ").strip()
        
        if choice == "1":
            peers = list_peers()
            if not peers:
                print(Fore.YELLOW + Style.BRIGHT + "\n⚠️ No peers connected")
            else:
                print(Fore.CYAN + Style.BRIGHT + "\n🔌 Connected Peers:")
                for i, peer in enumerate(peers):
                    print(f"{i+1}. {peer[0]}:{peer[1]}")
                    
        elif choice == "2":
            ip = input("Peer IP: ")
            port = int(input("Peer port: "))
            if add_peer(ip, port):
                print(Fore.GREEN + Style.BRIGHT + "\n✅ Peer added")
            else:
                print(Fore.RED + Style.BRIGHT + "\n❌ Failed to add peer")
                
        elif choice == "3":
            ip = input("Peer IP: ")
            port = int(input("Peer port: "))
            if remove_peer(ip, port):
                print(Fore.GREEN + Style.BRIGHT + "\n✅ Peer removed")
            else:
                print(Fore.RED + Style.BRIGHT + "\n❌ Peer not found")
                
        elif choice == "4":
            responsive = ping_peers()
            print(Fore.CYAN + Style.BRIGHT + f"\n📶 {len(responsive)}/{len(PEERS)} peers responsive")
            
        elif choice == "5":
            broadcast_peer_list()
            print(Fore.GREEN + Style.BRIGHT + "\n✅ Peer list broadcasted")
            
        elif choice == "6":
            filename = input("Filename (default: peers.json): ") or "peers.json"
            if save_peers(filename):
                print(Fore.GREEN + Style.BRIGHT + "\n✅ Peers saved")
            else:
                print(Fore.RED + Style.BRIGHT + "\n❌ Failed to save peers")
                
        elif choice == "7":
            filename = input("Filename (default: peers.json): ") or "peers.json"
            if load_peers(filename):
                print(Fore.GREEN + Style.BRIGHT + "\n✅ Peers loaded")
            else:
                print(Fore.RED + Style.BRIGHT + "\n❌ Failed to load peers")
                
        elif choice == "8":
            print(Fore.CYAN + Style.BRIGHT + "\n📊 Network Metrics:")
            print(f"Connected peers: {len(PEERS)}")
            print(f"Pending transactions: {len(pending_transactions)}")
            print(f"Blockchain height: {len(blockchain)}")
            print(f"Current difficulty: {difficulty}")
            
        elif choice == "9":
            return
            
        else:
            print(Fore.RED + Style.BRIGHT + "\n❌ Invalid choice")

def staking_menu():
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + "\n🏦 STAKING MENU")
        print("1. Stake coins")
        print("2. Unstake coins")
        print("3. Check staked balance")
        print("4. Back to main")
        
        choice = input(Fore.CYAN + Style.BRIGHT + "Enter choice: ").strip()
        
        if choice == "1":
            address = input("Your address: ")
            amount = float(input("Amount to stake: "))
            if stake_coins(address, amount):
                print(Fore.GREEN + Style.BRIGHT + "\n✅ Coins staked")
            else:
                print(Fore.RED + Style.BRIGHT + "\n❌ Staking failed")
                
        elif choice == "2":
            address = input("Your address: ")
            amount = float(input("Amount to unstake: "))
            if unstake_coins(address, amount):
                print(Fore.GREEN + Style.BRIGHT + "\n✅ Coins unstaked")
            else:
                print(Fore.RED + Style.BRIGHT + "\n❌ Unstaking failed")
                
        elif choice == "3":
            address = input("Your address: ")
            c.execute("SELECT staked FROM wallets WHERE wallet_address = ?", (address,))
            staked = c.fetchone()
            if staked:
                print(Fore.CYAN + Style.BRIGHT + f"\n🔒 Staked balance: {staked[0]} coins")
            else:
                print(Fore.RED + Style.BRIGHT + "\n❌ Wallet not found")
                
        elif choice == "4":
            return
            
        else:
            print(Fore.RED + Style.BRIGHT + "\n❌ Invalid choice")

def nft_menu():
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + "\n🖼️ NFT MENU")
        print("1. Create NFT")
        print("2. Transfer NFT")
        print("3. View my NFTs")
        print("4. Back to main")
        
        choice = input(Fore.CYAN + Style.BRIGHT + "Enter choice: ").strip()
        
        if choice == "1":
            creator = input("Your address: ")
            metadata = input("Metadata URI: ")
            nft_id = create_nft(creator, metadata)
            print(Fore.GREEN + Style.BRIGHT + f"\n✅ NFT created: {nft_id}")
            
        elif choice == "2":
            nft_id = input("NFT ID: ")
            sender = input("Your address: ")
            password = input("Wallet password: ")
            recipient = input("Recipient address: ")
            
            # Recover private key
            c.execute("SELECT seed_phrase, encrypted_private_key FROM wallets WHERE wallet_address = ?", (sender,))
            result = c.fetchone()
            if not result:
                print(Fore.RED + Style.BRIGHT + "\n❌ Wallet not found")
                continue
                
            seed, enc_pk = result
            try:
                private_key = decrypt_private_key(enc_pk, password, seed)
                if transfer_nft(nft_id, sender, recipient, private_key):
                    print(Fore.GREEN + Style.BRIGHT + "\n✅ NFT transferred")
                else:
                    print(Fore.RED + Style.BRIGHT + "\n❌ Transfer failed")
            except:
                print(Fore.RED + Style.BRIGHT + "\n❌ Invalid password")
                
        elif choice == "3":
            address = input("Your address: ")
            c.execute("SELECT id, metadata_uri FROM nfts WHERE owner = ?", (address,))
            nfts = c.fetchall()
            if not nfts:
                print(Fore.YELLOW + Style.BRIGHT + "\n⚠️ No NFTs found")
            else:
                print(Fore.CYAN + Style.BRIGHT + "\n🖼️ Your NFTs:")
                for nft in nfts:
                    print(f"{nft[0]} - {nft[1]}")
                    
        elif choice == "4":
            return
            
        else:
            print(Fore.RED + Style.BRIGHT + "\n❌ Invalid choice")

def contract_menu():
    global contract_vm
    if not contract_vm:
        contract_vm = ContractVM()
        
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + "\n🤖 SMART CONTRACT MENU")
        print("1. Deploy contract")
        print("2. Execute contract")
        print("3. View contract")
        print("4. Back to main")
        
        choice = input(Fore.CYAN + Style.BRIGHT + "Enter choice: ").strip()
        
        if choice == "1":
            creator = input("Your address: ")
            code = input("Contract code: ")
            address = contract_vm.deploy_contract(code, creator)
            print(Fore.GREEN + Style.BRIGHT + f"\n✅ Contract deployed at: {address}")
            
        elif choice == "2":
            contract_address = input("Contract address: ")
            function = input("Function to call: ")
            args = input("Arguments (comma separated): ").split(",")
            result = contract_vm.execute_contract(contract_address, function, args, creator)
            print(Fore.GREEN + Style.BRIGHT + f"\n✅ Execution result: {result}")
            
        elif choice == "3":
            contract_address = input("Contract address: ")
            c.execute("SELECT * FROM contracts WHERE address = ?", (contract_address,))
            contract = c.fetchone()
            if contract:
                print(Fore.CYAN + Style.BRIGHT + "\n📝 Contract Details:")
                print(f"Address: {contract[0]}")
                print(f"Creator: {contract[2]}")
                print(f"Balance: {contract[3]} coins")
                print(f"Code: {contract[1]}")
            else:
                print(Fore.RED + Style.BRIGHT + "\n❌ Contract not found")
                
        elif choice == "4":
            return
            
        else:
            print(Fore.RED + Style.BRIGHT + "\n❌ Invalid choice")

def governance_menu():
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + "\n🗳️ GOVERNANCE MENU")
        print("1. Create proposal")
        print("2. Vote on proposal")
        print("3. List proposals")
        print("4. Execute proposal")
        print("5. Back to main")
        
        choice = input(Fore.CYAN + Style.BRIGHT + "Enter choice: ").strip()
        
        if choice == "1":
            creator = input("Your address: ")
            description = input("Proposal description: ")
            options = input("Options (comma separated): ").split(",")
            proposal_id = create_proposal(creator, description, options)
            print(Fore.GREEN + Style.BRIGHT + f"\n✅ Proposal created: {proposal_id}")
            
        elif choice == "2":
            proposal_id = input("Proposal ID: ")
            voter = input("Your address: ")
            option = input("Option to vote for: ")
            amount = float(input("Stake amount: "))
            if vote_on_proposal(proposal_id, voter, option, amount):
                print(Fore.GREEN + Style.BRIGHT + "\n✅ Vote submitted")
            else:
                print(Fore.RED + Style.BRIGHT + "\n❌ Voting failed")
                
        elif choice == "3":
            c.execute("SELECT id, description, options FROM proposals")
            proposals = c.fetchall()
            if not proposals:
                print(Fore.YELLOW + Style.BRIGHT + "\n⚠️ No proposals found")
            else:
                print(Fore.CYAN + Style.BRIGHT + "\n📋 Proposals:")
                for proposal in proposals:
                    print(f"{proposal[0]} - {proposal[1]}")
                    print(f"Options: {proposal[2]}")
                    
        elif choice == "4":
            proposal_id = input("Proposal ID: ")
            if execute_proposal(proposal_id):
                print(Fore.GREEN + Style.BRIGHT + "\n✅ Proposal executed")
            else:
                print(Fore.RED + Style.BRIGHT + "\n❌ Execution failed")
                
        elif choice == "5":
            return
            
        else:
            print(Fore.RED + Style.BRIGHT + "\n❌ Invalid choice")

def channel_menu():
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + "\n🔁 PAYMENT CHANNEL MENU")
        print("1. Open channel")
        print("2. Update channel")
        print("3. Close channel")
        print("4. View my channels")
        print("5. Back to main")
        
        choice = input(Fore.CYAN + Style.BRIGHT + "Enter choice: ").strip()
        
        if choice == "1":
            party1 = input("Your address: ")
            party2 = input("Counterparty address: ")
            amount1 = float(input("Your deposit: "))
            amount2 = float(input("Counterparty deposit: "))
            channel_id = open_payment_channel(party1, party2, amount1, amount2)
            print(Fore.GREEN + Style.BRIGHT + f"\n✅ Channel opened: {channel_id}")
            
        elif choice == "2":
            channel_id = input("Channel ID: ")
            balance1 = float(input("Your new balance: "))
            balance2 = float(input("Counterparty new balance: "))
            # In a real implementation, we'd need signatures
            print(Fore.YELLOW + Style.BRIGHT + "\n⚠️ Signature requirement skipped in demo")
            if update_payment_channel(channel_id, balance1, balance2, "sig1", "sig2"):
                print(Fore.GREEN + Style.BRIGHT + "\n✅ Channel updated")
            else:
                print(Fore.RED + Style.BRIGHT + "\n❌ Update failed")
                
        elif choice == "3":
            channel_id = input("Channel ID: ")
            # In a real implementation, we'd need signature
            print(Fore.YELLOW + Style.BRIGHT + "\n⚠️ Signature requirement skipped in demo")
            if close_payment_channel(channel_id, "signature"):
                print(Fore.GREEN + Style.BRIGHT + "\n✅ Channel closed")
            else:
                print(Fore.RED + Style.BRIGHT + "\n❌ Closure failed")
                
        elif choice == "4":
            address = input("Your address: ")
            c.execute("SELECT id, party1, party2, balance1, balance2 FROM payment_channels WHERE party1 = ? OR party2 = ?", 
                      (address, address))
            channels = c.fetchall()
            if not channels:
                print(Fore.YELLOW + Style.BRIGHT + "\n⚠️ No channels found")
            else:
                print(Fore.CYAN + Style.BRIGHT + "\n🔁 Your Channels:")
                for channel in channels:
                    role = "Party1" if channel[1] == address else "Party2"
                    balance = channel[3] if role == "Party1" else channel[4]
                    print(f"{channel[0]} - {channel[1]} & {channel[2]} - Your balance: {balance}")
                    
        elif choice == "5":
            return
            
        else:
            print(Fore.RED + Style.BRIGHT + "\n❌ Invalid choice")

def economy_menu():
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + "\n📈 ECONOMY MENU")
        print("1. Show supply")
        print("2. Show liquidity")
        print("3. Burn coins")
        print("4. Show burned coins")
        print("5. Back to main")
        
        choice = input(Fore.CYAN + Style.BRIGHT + "Enter choice: ").strip()
        
        if choice == "1":
            show_supply()
            
        elif choice == "2":
            show_liquidity()
            
        elif choice == "3":
            address = input("Your address: ")
            amount = float(input("Amount to burn: "))
            burn_coins(address, amount)
            
        elif choice == "4":
            total_burned = get_total_burned()
            print(Fore.RED + Style.BRIGHT + f"\n🔥 Total Burned Coins: {total_burned}")
            
        elif choice == "5":
            return
            
        else:
            print(Fore.RED + Style.BRIGHT + "\n❌ Invalid choice")

# ============== MAIN APPLICATION ==============
def main():
    # Initialize components
    generate_ssl_cert()
    setup_nat_traversal()
    
    # Start P2P server
    threading.Thread(
        target=start_server, 
        args=(P2P_PORT, blockchain, pending_transactions),
        daemon=True
    ).start()
    logging.info(f"P2P server started on port {P2P_PORT}")
    
    # Load known peers
    load_peers()
    
    # Main menu
    print(Fore.GREEN + Style.BRIGHT + "\n" + "="*50)
    print(Fore.GREEN + Style.BRIGHT + f"🚀 {TARGET_NAME} v{TARGET_VERSION}")
    print(Fore.GREEN + Style.BRIGHT + "="*50)
    print(f"Shard ID: {shard_id}")
    print(f"Peers: {len(PEERS)}")
    print(f"Block height: {len(blockchain)}")
    
    while True:
        print(Fore.MAGENTA + Style.BRIGHT + "\n🏠 MAIN MENU")
        print("1. Wallet Operations")
        print("2. Transaction Operations")
        print("3. Block Operations")
        print("4. Network Operations")
        print("5. Staking Operations")
        print("6. NFT Operations")
        print("7. Smart Contract Operations")
        print("8. Governance Operations")
        print("9. Payment Channel Operations")
        print("10. Economy Overview")
        print("0. Exit")
        
        choice = input(Fore.CYAN + Style.BRIGHT + "Enter choice: ").strip()
        
        if choice == "1":
            wallet_menu()
        elif choice == "2":
            transaction_menu()
        elif choice == "3":
            block_menu()
        elif choice == "4":
            network_menu()
        elif choice == "5":
            staking_menu()
        elif choice == "6":
            nft_menu()
        elif choice == "7":
            contract_menu()
        elif choice == "8":
            governance_menu()
        elif choice == "9":
            channel_menu()
        elif choice == "10":
            economy_menu()
        elif choice == "0":
            print(Fore.GREEN + Style.BRIGHT + "\n👋 Exiting... Goodbye!")
            break
        else:
            print(Fore.RED + Style.BRIGHT + "\n❌ Invalid choice")

if __name__ == "__main__":
    main()
