import socket
import threading
import json
import ssl
import time
import logging
import sqlite3
import miniupnpc
import stun
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hashlib
import os
import base64
import datetime


# Initialize colorama for colored output
from colorama import Fore, Style, init
init(autoreset=True)

# Enhanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
    handlers=[
        logging.FileHandler("p2p_network.log"),
        logging.StreamHandler()
    ]
)

# Global state
PEERS = set()
PEER_SCORES = {}
BLOCK_VOTES = {}
VALIDATORS = set()
CONN = sqlite3.connect("blockchain.db", check_same_thread=False)
C = CONN.cursor()

# Configuration
MIN_STAKE = 1000  # Minimum stake to become a validator
#P2P_HOST =
P2P_PORT = 5000
SSL_CERT = "cert.pem"
SSL_KEY = "key.pem"
BOOTSTRAP_NODES = [("seed1.coinium.com", 5000), ("seed2.coinium.com", 5000)]
MIN_PEER_SCORE = 30
MAX_PEERS = 50
BLOCK_PROPAGATION_DELAY = 2  # seconds

def setup_nat_traversal():
    """Configure NAT traversal using UPnP and STUN"""
    # UPnP port forwarding
    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 200
        upnp.discover()
        upnp.selectigd()
        upnp.addportmapping(P2P_PORT, 'TCP', upnp.lanaddr, P2P_PORT, 'Coinium', '')
        logging.info(f"UPnP port forwarding enabled: {upnp.lanaddr}:{P2P_PORT}")
    except Exception as e:
        logging.error(f"UPnP failed: {e}")
    
    # STUN for public IP discovery
    try:
        nat_type, public_ip, public_port = stun.get_ip_info()
        if public_ip and public_port:
            add_peer(public_ip, public_port)
            logging.info(f"Public IP discovered: {public_ip}:{public_port}")
            return public_ip, public_port
    except Exception as e:
        logging.error(f"STUN failed: {e}")
    
    return None, None

def send_message(peer, message, use_ssl=True, timeout=5):
    """Send message to a peer with SSL encryption"""
    ip, port = peer
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        if use_ssl:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.load_verify_locations('cacert.pem')
            ssock = context.wrap_socket(sock, server_hostname=ip)
            ssock.connect((ip, port))
            ssock.sendall(json.dumps(message).encode())
            ssock.close()
        else:
            sock.connect((ip, port))
            sock.sendall(json.dumps(message).encode())
            sock.close()
            
        update_peer_score(peer, 1)  # Reward for successful communication
        return True
    except Exception as e:
        logging.error(f"Failed to send message to {peer}: {e}")
        update_peer_score(peer, -2)  # Penalize for failure
        return False

def broadcast(message, use_ssl=True, exclude_peer=None):
    """Broadcast message to all peers with delay to prevent flooding"""
    time.sleep(BLOCK_PROPAGATION_DELAY)  # Prevent network flooding
    for peer in list(PEERS):
        if exclude_peer and peer == exclude_peer:
            continue
        if PEER_SCORES.get(peer, 100) >= MIN_PEER_SCORE:  # Only send to good peers
            threading.Thread(
                target=send_message, 
                args=(peer, message, use_ssl)
            ).start()

def add_peer(ip, port):
    """Add a new peer to the network"""
    peer = (ip, port)
    if peer not in PEERS and len(PEERS) < MAX_PEERS:
        PEERS.add(peer)
        PEER_SCORES[peer] = 100  # Initial score
        logging.info(f"Added peer: {ip}:{port}")
        return True
    return False

def remove_peer(ip, port):
    """Remove a peer from the network"""
    peer = (ip, port)
    if peer in PEERS:
        PEERS.remove(peer)
        if peer in PEER_SCORES:
            del PEER_SCORES[peer]
        logging.info(f"Removed peer: {ip}:{port}")
        return True
    return False

def update_peer_score(peer, delta):
    """Update a peer's reputation score"""
    if peer not in PEER_SCORES:
        PEER_SCORES[peer] = 100
    PEER_SCORES[peer] = max(0, min(200, PEER_SCORES[peer] + delta))
    
    # Auto-blacklist low scoring peers
    if PEER_SCORES[peer] < MIN_PEER_SCORE:
        remove_peer(*peer)
        logging.warning(f"Blacklisted peer {peer} for low score")

def list_peers():
    """List all active peers"""
    return list(PEERS)

def save_peers(filename='peers.json'):
    """Save peers to a file"""
    try:
        with open(filename, 'w') as f:
            json.dump(list(PEERS), f)
        return True
    except Exception as e:
        logging.error(f"Error saving peers: {e}")
        return False

def load_peers(filename='peers.json'):
    """Load peers from a file"""
    if not os.path.exists("peers.json"):
     with open("peers.json", "w") as f:
        json.dump([], f)

    try:
        with open(filename, 'r') as f:
            content = f.read().strip()
            if not content:
                return set()
        return set(tuple(peer) for peer in json.loads(content))
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Error loading peers: {e}")
    return set()

def broadcast_peer_list(use_ssl=True):
    """Broadcast the current peer list to all peers"""
    peer_list = list_peers()
    message = {"type": "PEER_LIST", "data": peer_list}
    broadcast(message, use_ssl)

def ping_peers(timeout=2):
    """Check connectivity to all peers"""
    responsive_peers = []
    for peer in list_peers():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(peer)
            sock.close()
            update_peer_score(peer, 1)
            responsive_peers.append(peer)
        except:
            update_peer_score(peer, -3)
    return responsive_peers

def validate_block_signature(block):
    """Validate block signature using validator's public key"""
    try:
        validator = block.get("validator")
        signature = block.get("signature")
        if not validator or not signature:
            return False
            
        # Fetch validator's public key
        C.execute("SELECT public_key FROM wallets WHERE wallet_address = ?", (validator,))
        result = C.fetchone()
        if not result:
            return False
            
        public_key = serialization.load_der_public_key(
            bytes.fromhex(result[0]),
            backend=default_backend()
        )
        
        # Create a copy of block without signature for verification
        block_copy = block.copy()
        block_copy.pop("signature", None)
        
        # Verify signature
        return public_key.verify(
            bytes.fromhex(signature),
            json.dumps(block_copy, sort_keys=True).encode(),
            ec.ECDSA(hashes.SHA256())
        )
    except Exception as e:
        logging.error(f"Block signature validation failed: {e}")
        return False

def handle_block_vote(block_hash, voter):
    """Process vote for a block"""
    if block_hash not in BLOCK_VOTES:
        BLOCK_VOTES[block_hash] = set()
    
    if voter not in BLOCK_VOTES[block_hash]:
        BLOCK_VOTES[block_hash].add(voter)
        logging.info(f"Vote received for block {block_hash[:8]}... (Total: {len(BLOCK_VOTES[block_hash])})")
        
        # Check if supermajority reached
        if len(BLOCK_VOTES[block_hash]) > len(VALIDATORS) * 2 / 3:
            logging.info(f"Block {block_hash[:8]}... achieved consensus!")
            return True
    return False

def get_validators():
    """Fetch current validators from database"""
    VALIDATORS.clear()
    C.execute("SELECT wallet_address FROM wallets WHERE staked >= ?", (MIN_STAKE,))
    for row in C.fetchall():
        VALIDATORS.add(row[0])
    return VALIDATORS

def handle_client(conn, addr, blockchain, pending_transactions, use_ssl=False):
    """Handle incoming client connections"""
    try:
        data = conn.recv(65536)  # 64KB max
        if not data:
            return
            
        message = json.loads(data.decode())
        msg_type = message.get("type")
        
        if msg_type == "NEW_TRANSACTION":
            tx = message["data"]
            if tx not in pending_transactions:
                pending_transactions.append(tx)
                logging.info(f"Received new transaction from {addr}")
                # Re-broadcast to other peers
                broadcast({"type": "NEW_TRANSACTION", "data": tx}, exclude_peer=addr)
                
        elif msg_type == "NEW_BLOCK":
            block = message["data"]
            if validate_block_signature(block) and block not in blockchain:
                blockchain.append(block)
                logging.info(f"Valid block received from {addr}: {block['hash'][:8]}...")
                # Re-broadcast to other peers
                broadcast({"type": "NEW_BLOCK", "data": block}, exclude_peer=addr)
                
                # Automatically vote for valid blocks
                if addr[0] in VALIDATORS:  # Only validators vote
                    vote_msg = {
                        "type": "BLOCK_VOTE",
                        "block_hash": block["hash"],
                        "voter": addr[0]
                    }
                    broadcast(vote_msg)
                
        elif msg_type == "BLOCK_VOTE":
            block_hash = message["block_hash"]
            voter = message["voter"]
            if handle_block_vote(block_hash, voter):
                # Consensus reached, process block
                logging.info(f"Consensus reached for block {block_hash[:8]}...")
                
        elif msg_type == "PEER_LIST":
            new_peers = message["data"]
            for peer in new_peers:
                if peer not in PEERS:
                    add_peer(peer[0], peer[1])
                    
        elif msg_type == "PING":
            # Respond to ping
            conn.sendall(json.dumps({"type": "PONG"}).encode())
            
        elif msg_type == "PONG":
            # Handle pong response
            update_peer_score(addr, 1)
            
        elif msg_type == "VALIDATOR_LIST":
            # Update validator set
            new_validators = set(message["data"])
            VALIDATORS.update(new_validators)
            
        else:
            logging.warning(f"Unknown message type from {addr}: {msg_type}")
            
    except Exception as e:
        logging.error(f"Error handling client {addr}: {e}")
        update_peer_score(addr, -5)
    finally:
        conn.close()

def start_server(port, blockchain, pending_transactions, use_ssl=True, certfile=SSL_CERT, keyfile=SSL_KEY):
    """Start the P2P server"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(10)
    logging.info(f"P2P server listening on port {port} (SSL: {use_ssl})...")
    
    # Configure SSL if enabled
    ssl_context = None
    if use_ssl:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    
    while True:
        try:
            client, addr = server.accept()
            if use_ssl:
                client = ssl_context.wrap_socket(client, server_side=True)
                
            threading.Thread(
                target=handle_client, 
                args=(client, addr, blockchain, pending_transactions, use_ssl),
                daemon=True
            ).start()
        except Exception as e:
            logging.error(f"Server error: {e}")

def bootstrap_network():
    """Connect to bootstrap nodes"""
    for node in BOOTSTRAP_NODES:
        add_peer(node[0], node[1])
        send_message(node, {"type": "PEER_REQUEST"})
        
    # Request validator list
    broadcast({"type": "VALIDATOR_REQUEST"})

def peer_discovery():
    """Periodically discover new peers"""
    while True:
        broadcast_peer_list()
        time.sleep(300)  # Every 5 minutes

def start_peer_discovery():
    """Start peer discovery in background"""
    threading.Thread(target=peer_discovery, daemon=True).start()

def generate_ssl_cert():
    """Generate self-signed SSL certificate if not exists"""
    if not os.path.exists(SSL_CERT) or not os.path.exists(SSL_KEY):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"Coinium Node"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Coinium Network"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Save certificate
        with open(SSL_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Save private key
        with open(SSL_KEY, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        logging.info("Generated new SSL certificate")

# Initialize network
generate_ssl_cert()
setup_nat_traversal()
#get_validators()  # Load initial validators
