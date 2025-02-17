import streamlit as st
import socketio
import json
import base64
from Crypto.Cipher import AES
from ecdsa import SigningKey, NIST384p
from ecdsa.util import string_to_number

# Setup SocketIO connection to backend
sio = socketio.Client()

# Global variables for session
aes_key = None
ecc_sk = None  # Elliptic Curve Private Key (for signing)
ecc_pk = None  # Elliptic Curve Public Key (for key exchange)
shared_secret = None

# Function to generate AES encryption key
def generate_aes_key():
    return base64.urlsafe_b64encode(bytes(str(ecc_sk.to_string()), 'utf-8')[:16])

# Encrypt Message with AES
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

# Decrypt Message with AES
def decrypt_message(encrypted_message, key):
    encrypted_data = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        decrypted_message = cipher.decrypt_and_verify(ciphertext, tag).decode()
        return decrypted_message
    except ValueError:
        return "Error: Decryption failed."

# SocketIO Event: When server sends a message
@sio.event
def message(data):
    decrypted_message = decrypt_message(data['message'], aes_key)
    st.write(f"Received: {decrypted_message}")

# Streamlit UI Components
st.title('Secure Chat Application 🔐💬')

# User Input for Message
message = st.text_input("Enter message:", "")

# Connect Button
if st.button("Connect to Server"):
    # Connect to SocketIO backend
    sio.connect('http://localhost:5000')

    # ECC Key generation (using NIST384p curve)
    ecc_sk = SigningKey.generate(curve=NIST384p)
    ecc_pk = ecc_sk.get_verifying_key()

    # Generate AES key using the ECC private key
    aes_key = generate_aes_key()

    # Send the public key to the backend for secure communication
    sio.emit('connect_client', {
        'public_key': base64.b64encode(ecc_pk.to_string()).decode()
    })

# Sending Encrypted Message
if st.button("Send Encrypted Message"):
    if message != "":
        encrypted_message = encrypt_message(message, aes_key)
        sio.emit('send_message', {
            'message': encrypted_message
        })
        st.write(f"Sent: {message}")
    else:
        st.write("Please enter a message to send.")

