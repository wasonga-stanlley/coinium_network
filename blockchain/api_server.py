from flask import Flask, jsonify, request
import sqlite3
import json
import time
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import threading
import os

app = Flask(__name__)

# Database setup
conn = sqlite3.connect("blockchain.db", check_same_thread=False)
c = conn.cursor()

# API configuration
API_PORT = 5001
API_HOST = "127.0.0.1"  # Only listen on localhost for security

@app.route('/')
def index():
    return jsonify({
        "name": "Coinium Blockchain API",
        "version": "2.0",
        "endpoints": {
            "/blockchain": "Get blockchain info",
            "/block/<height>": "Get block by height",
            "/transaction/<txid>": "Get transaction by ID",
            "/wallet/<address>": "Get wallet info",
            "/peers": "List connected peers",
            "/validators": "List current validators",
            "/nft/<id>": "Get NFT details",
            "/contract/<address>": "Get contract details",
            "/proposal/<id>": "Get proposal details",
            "/send": "Submit new transaction (POST)"
        }
    })

@app.route('/blockchain')
def blockchain_info():
    c.execute("SELECT COUNT(*) FROM blocks")
    block_height = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM transactions")
    tx_count = c.fetchone()[0]
    
    c.execute("SELECT SUM(balance) FROM wallets")
    total_supply = c.fetchone()[0] or 0
    
    c.execute("SELECT SUM(staked) FROM wallets")
    total_staked = c.fetchone()[0] or 0
    
    return jsonify({
        "block_height": block_height,
        "total_transactions": tx_count,
        "total_supply": total_supply,
        "total_staked": total_staked,
        "consensus": "PoS/PoW Hybrid"
    })

@app.route('/block/<int:height>')
def get_block(height):
    c.execute("SELECT * FROM blocks WHERE block_index = ?", (height,))
    block = c.fetchone()
    if not block:
        return jsonify({"error": "Block not found"}), 404
        
    # Format block data
    block_data = {
        "height": block[1],
        "hash": block[6],
        "previous_hash": block[2],
        "timestamp": block[3],
        "merkle_root": block[4],
        "nonce": block[5],
        "difficulty": block[7],
        "validator": block[8],
        "vote_count": block[9]
    }
    
    # Get transactions
    c.execute("SELECT * FROM transactions WHERE block_height = ?", (height,))
    transactions = []
    for tx in c.fetchall():
        transactions.append({
            "id": tx[1],
            "sender": tx[2],
            "recipient": tx[3],
            "amount": tx[4],
            "fee": tx[5],
            "timestamp": tx[6]
        })
    
    block_data["transactions"] = transactions
    return jsonify(block_data)

@app.route('/transaction/<txid>')
def get_transaction(txid):
    c.execute("SELECT * FROM transactions WHERE tx_hash = ?", (txid,))
    tx = c.fetchone()
    if not tx:
        return jsonify({"error": "Transaction not found"}), 404
        
    return jsonify({
        "id": tx[1],
        "block_height": tx[10],
        "sender": tx[2],
        "recipient": tx[3],
        "amount": tx[4],
        "fee": tx[5],
        "timestamp": tx[6],
        "signature": tx[7],
        "is_coinbase": bool(tx[8]),
        "shard": tx[9]
    })

@app.route('/wallet/<address>')
def get_wallet(address):
    c.execute("SELECT * FROM wallets WHERE wallet_address = ?", (address,))
    wallet = c.fetchone()
    if not wallet:
        return jsonify({"error": "Wallet not found"}), 404
        
    # Get transaction history
    c.execute("SELECT * FROM transactions WHERE sender = ? OR recipient = ? ORDER BY timestamp DESC LIMIT 50", 
              (address, address))
    transactions = []
    for tx in c.fetchall():
        transactions.append({
            "id": tx[1],
            "direction": "out" if tx[2] == address else "in",
            "counterparty": tx[3] if tx[2] == address else tx[2],
            "amount": tx[4],
            "timestamp": tx[6]
        })
    
    # Get NFT holdings
    c.execute("SELECT * FROM nfts WHERE owner = ?", (address,))
    nfts = [{"id": nft[0], "metadata": nft[3]} for nft in c.fetchall()]
    
    return jsonify({
        "address": wallet[1],
        "balance": wallet[6],
        "staked": wallet[7],
        "public_key": wallet[2],
        "transactions": transactions,
        "nfts": nfts,
        "last_online": wallet[8]
    })

@app.route('/peers')
def get_peers():
    # This would need integration with p2pnetworking module
    # For demo purposes, we'll return a static list
    return jsonify([
        {"ip": "192.168.1.10", "port": 5000, "score": 95},
        {"ip": "203.0.113.5", "port": 5000, "score": 88},
        {"ip": "198.51.100.22", "port": 5000, "score": 92}
    ])

@app.route('/validators')
def get_validators():
    c.execute("SELECT wallet_address, staked FROM wallets WHERE staked >= ? ORDER BY staked DESC", (100,))
    validators = [{"address": row[0], "stake": row[1]} for row in c.fetchall()]
    return jsonify(validators)

@app.route('/nft/<nft_id>')
def get_nft(nft_id):
    c.execute("SELECT * FROM nfts WHERE id = ?", (nft_id,))
    nft = c.fetchone()
    if not nft:
        return jsonify({"error": "NFT not found"}), 404
        
    # Get transaction history
    c.execute("SELECT * FROM nft_transfers WHERE nft_id = ? ORDER BY timestamp DESC", (nft_id,))
    transfers = [{"from": tx[2], "to": tx[3], "timestamp": tx[4]} for tx in c.fetchall()]
    
    return jsonify({
        "id": nft[0],
        "creator": nft[1],
        "owner": nft[2],
        "metadata_uri": nft[3],
        "created_at": nft[4],
        "transfers": transfers
    })

@app.route('/contract/<address>')
def get_contract(address):
    c.execute("SELECT * FROM contracts WHERE address = ?", (address,))
    contract = c.fetchone()
    if not contract:
        return jsonify({"error": "Contract not found"}), 404
        
    return jsonify({
        "address": contract[0],
        "creator": contract[2],
        "balance": contract[3],
        "code": contract[1],
        "storage": json.loads(contract[4]) if contract[4] else {}
    })

@app.route('/proposal/<proposal_id>')
def get_proposal(proposal_id):
    c.execute("SELECT * FROM proposals WHERE id = ?", (proposal_id,))
    proposal = c.fetchone()
    if not proposal:
        return jsonify({"error": "Proposal not found"}), 404
        
    return jsonify({
        "id": proposal[0],
        "creator": proposal[1],
        "description": proposal[2],
        "options": json.loads(proposal[3]),
        "votes": json.loads(proposal[4]),
        "start_time": proposal[5],
        "end_time": proposal[6],
        "executed": bool(proposal[7])
    })

@app.route('/send', methods=['POST'])
def send_transaction():
    """Submit a new transaction to the network"""
    data = request.json
    required_fields = ["sender", "recipient", "amount", "signature"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
        
    # In a real implementation, this would broadcast to P2P network
    # For demo, we'll just log and pretend
    tx_hash = hashlib.sha256(json.dumps(data).encode()).hexdigest()
    logging.info(f"Received transaction: {tx_hash}")
    
    return jsonify({
        "status": "accepted",
        "txid": tx_hash,
        "message": "Transaction will be processed in the next block"
    })

def start_api_server():
    """Start the API server"""
    logging.info(f"Starting API server on port {API_PORT}")
    app.run(host=API_HOST, port=API_PORT)

if __name__ == "__main__":
    # Start in a separate thread
    threading.Thread(target=start_api_server, daemon=True).start()
    
    # Keep main thread alive
    while True:
        time.sleep(1)
