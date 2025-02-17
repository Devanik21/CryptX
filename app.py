from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from ecdsa import SigningKey, VerifyingKey, NIST256p
import base64
import json

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Store user keys (For simplicity, using in-memory dictionary)
user_keys = {}

def generate_ecc_keys():
    """Generates an ECC private/public key pair."""
    private_key = SigningKey.generate(curve=NIST256p)
    public_key = private_key.verifying_key
    return private_key, public_key

def encrypt_message(message, aes_key):
    """Encrypts a message using AES."""
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_message(encrypted_message, aes_key):
    """Decrypts an AES-encrypted message."""
    data = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def generate_hmac(message, key):
    """Creates an HMAC signature for integrity verification."""
    h = HMAC.new(key, message.encode(), digestmod=SHA256)
    return base64.b64encode(h.digest()).decode()

def verify_hmac(message, key, received_hmac):
    """Verifies an HMAC signature."""
    expected_hmac = generate_hmac(message, key)
    return expected_hmac == received_hmac

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    """Generates ECC key pair for a new user."""
    user_id = request.json.get("user_id")
    private_key, public_key = generate_ecc_keys()
    user_keys[user_id] = {"private": private_key, "public": public_key}
    return jsonify({"public_key": public_key.to_pem().decode()})

@app.route('/derive_shared_key', methods=['POST'])
def derive_shared_key():
    """Derives a shared ECC key using ECDH."""
    user_id = request.json.get("user_id")
    peer_public_key_pem = request.json.get("peer_public_key")

    if user_id not in user_keys:
        return jsonify({"error": "User not found"}), 400

    private_key = user_keys[user_id]["private"]
    peer_public_key = VerifyingKey.from_pem(peer_public_key_pem)

    shared_secret = private_key.privkey.secret_multiplier * peer_public_key.pubkey.point.x()
    aes_key = SHA256.new(str(shared_secret).encode()).digest()[:16]  # Convert to AES key

    user_keys[user_id]["aes_key"] = aes_key
    return jsonify({"aes_key": base64.b64encode(aes_key).decode()})

@socketio.on("send_message")
def handle_send_message(data):
    """Handles sending encrypted messages via WebSockets."""
    sender = data["sender"]
    receiver = data["receiver"]
    message = data["message"]

    if sender not in user_keys or receiver not in user_keys:
        emit("error", {"error": "User not found"})
        return

    aes_key = user_keys[sender]["aes_key"]
    encrypted_message = encrypt_message(message, aes_key)
    hmac_signature = generate_hmac(message, aes_key)

    emit("receive_message", {
        "sender": sender,
        "receiver": receiver,
        "message": encrypted_message,
        "hmac": hmac_signature
    }, broadcast=True)

@socketio.on("receive_message")
def handle_receive_message(data):
    """Handles receiving encrypted messages."""
    receiver = data["receiver"]
    encrypted_message = data["message"]
    hmac_signature = data["hmac"]

    if receiver not in user_keys:
        emit("error", {"error": "User not found"})
        return

    aes_key = user_keys[receiver]["aes_key"]
    decrypted_message = decrypt_message(encrypted_message, aes_key)

    if not verify_hmac(decrypted_message, aes_key, hmac_signature):
        emit("error", {"error": "Message integrity compromised!"})
        return

    emit("message_received", {
        "receiver": receiver,
        "message": decrypted_message
    })

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5000)
