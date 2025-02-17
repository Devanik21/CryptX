import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socketio

# Generate ECC keys for sender and receiver
private_key_sender = ec.generate_private_key(ec.SECP384R1())
private_key_receiver = ec.generate_private_key(ec.SECP384R1())

# Derive public keys for exchange
public_key_sender = private_key_sender.public_key()
public_key_receiver = private_key_receiver.public_key()

# Perform key exchange (ECDH) to generate shared secret
shared_secret_sender = private_key_sender.exchange(ec.ECDH(), public_key_receiver)
shared_secret_receiver = private_key_receiver.exchange(ec.ECDH(), public_key_sender)

# Ensure the shared secrets are equal
assert shared_secret_sender == shared_secret_receiver

# Use PBKDF2 to derive a symmetric AES key from the shared secret
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"your_salt", iterations=100000)
aes_key = kdf.derive(shared_secret_sender)

# Encrypt the message with AES
def encrypt_message(aes_key, message):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce=b"random_nonce"))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return ciphertext

# Decrypt the message with AES
def decrypt_message(aes_key, ciphertext):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce=b"random_nonce"))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.decode()

# Set up socket.io client
sio = socketio.Client()

# Connect to the server
sio.connect('http://localhost:5000')

# Listen for incoming messages from server
@sio.event
def connect():
    print("Connected to server!")

@sio.event
def disconnect():
    print("Disconnected from server!")

# Listen for incoming messages
@sio.on('chat_message')
def handle_message(data):
    encrypted_message = data['message']
    decrypted_message = decrypt_message(aes_key, encrypted_message)
    print(f"Received encrypted message: {encrypted_message}")
    print(f"Decrypted message: {decrypted_message}")

# Send a message
def send_message(message):
    encrypted_message = encrypt_message(aes_key, message)
    sio.emit('chat_message', {'message': encrypted_message})
    print(f"Sent encrypted message: {encrypted_message}")

# Example usage
if __name__ == '__main__':
    message = "Hello, this is a secret message!"
    send_message(message)
    sio.wait()  # Wait for incoming messages
