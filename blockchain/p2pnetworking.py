import socket
import threading
import json
import ssl
import time

PEERS = set()  # Set of (ip, port) tuples

def send_message(peer, message, use_ssl=False, timeout=10):
    ip, port = peer
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if use_ssl:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            sock = context.wrap_socket(sock, server_hostname=ip)
        sock.connect((ip, port))
        sock.sendall(json.dumps(message).encode())
        sock.close()
    except Exception as e:
        print(f"Failed to send message to {peer}: {e}")

def broadcast(message, use_ssl=False):
    for peer in PEERS:
        send_message(peer, message, use_ssl)

def add_peer(ip, port):
    PEERS.add((ip, port))
    print(f"Added peer: {ip}:{port}")

def remove_peer(ip, port):
    PEERS.discard((ip, port))
    print(f"Removed peer: {ip}:{port}")

def list_peers():
    return list(PEERS)

def save_peers(filename='peers.json'):
    with open(filename, 'w') as f:
        json.dump(list(PEERS), f)

def load_peers(filename='peers.json'):
    global PEERS
    try:
        with open(filename, 'r') as f:
            PEERS = set(tuple(peer) for peer in json.load(f))
        print(f"Loaded {len(PEERS)} peers from {filename}.")
    except FileNotFoundError:
        print("No peers file found, starting with an empty peer list.")
    except json.JSONDecodeError:
        print("Error decoding peers file, starting with an empty peer list.")

def broadcast_peer_list(use_ssl=False):
    peer_list = list_peers()
    for peer in peer_list:
        message = {
            "type": "PEER_LIST",
            "data": peer_list
        }
        send_message(peer, message, use_ssl)

def ping_peers(timeout=5):
    for peer in list_peers():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(peer)
            sock.close()
            print(f"Pinged {peer} successfully.")
        except socket.error as e:
            print(f"Failed to ping {peer}: {e}")
            remove_peer(*peer)


def check_all_peers(timeout=5):
    """Check all peers and remove those that are unresponsive."""
    for peer in list_peers():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(peer)
            sock.close()
            send_message(peer, {"type": "PING"}, timeout=timeout)
            print(f"Peer {peer} is responsive.")
        except socket.error as e:
            print(f"Peer {peer} is unresponsive: {e}")
            remove_peer(*peer)

def periodic_peer_check(interval=60, timeout=5):
    """Periodically check all peers and remove unresponsive ones."""
    def run():
        while True:
            check_all_peers(timeout)
            time.sleep(interval)
    threading.Thread(target=run, daemon=True).start()




def handle_client(conn, addr, blockchain, pending_transactions, use_ssl=False):
    try:
        data = conn.recv(4096)
        if not data:
            return
        message = json.loads(data.decode())
        msg_type = message.get("type")
        if msg_type == "NEW_TRANSACTION":
            tx = message["data"]
            # Add to pending_transactions if not duplicate
            if tx not in pending_transactions:
                pending_transactions.append(tx)
                print(f"Received new transaction from {addr}: {tx}")
        elif msg_type == "NEW_BLOCK":
            block = message["data"]
            # Add block if valid and not duplicate
            if block not in blockchain:
                blockchain.append(block)
                print(f"Received new block from {addr}: {block['hash']}")
        elif msg_type == "REQUEST_CHAIN":
            # Send full chain to requester
            response = {"type": "FULL_CHAIN", "data": blockchain}
            conn.sendall(json.dumps(response).encode())
        elif msg_type == "FULL_CHAIN":
            # Replace local chain if received chain is longer and valid
            remote_chain = message["data"]
            if len(remote_chain) > len(blockchain):
                blockchain.clear()
                blockchain.extend(remote_chain)
                print(f"Chain replaced with longer chain from {addr}")
        elif msg_type == "PEER_LIST":
            new_peers = message["data"]
            for peer in new_peers:
                if peer not in PEERS:
                    PEERS.add(tuple(peer))
                    print(f"Added new peer from {addr}: {new_peers}")
        elif msg_type == "PING":
            # Respond to ping
            response = {"type": "PONG"}
            conn.sendall(json.dumps(response).encode())
        elif msg_type == "PONG":
            # Handle pong response if needed
            print(f"Received pong from {addr}")
        else:
            print(f"Unknown message type from {addr}: {msg_type}")
            
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()

def start_server(port, blockchain, pending_transactions, use_ssl=False, certfile=None, keyfile=None):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"P2P server listening on port {port}...")
    while True:
        client, addr = server.accept()
        if use_ssl:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
            client = context.wrap_socket(client, server_side=True)
        threading.Thread(target=handle_client, args=(client, addr, blockchain, pending_transactions, use_ssl)).start()
