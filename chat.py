import os
import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

# Function to generate ECC keys
def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Function to perform ECDH key exchange to derive shared secret
def ecdh_key_exchange(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

# Function to derive AES key from shared secret
def derive_aes_key(shared_secret):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"your_salt", iterations=100000)
    aes_key = kdf.derive(shared_secret)
    return aes_key

# Function to encrypt message using AES
def encrypt_message(aes_key, message):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce=b"random_nonce"))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return ciphertext, encryptor.tag

# Function to decrypt message using AES
def decrypt_message(aes_key, ciphertext, tag):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce=b"random_nonce", tag=tag))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.decode()

# Streamlit UI for chat
st.title('Secure Chat Application 🔐💬')

# Initialize ECC keys for sender and receiver
private_key_sender, public_key_sender = generate_ecc_keys()
private_key_receiver, public_key_receiver = generate_ecc_keys()

# Perform ECDH key exchange
shared_secret_sender = ecdh_key_exchange(private_key_sender, public_key_receiver)
shared_secret_receiver = ecdh_key_exchange(private_key_receiver, public_key_sender)

# Ensure shared secrets match
assert shared_secret_sender == shared_secret_receiver

# Derive AES key from the shared secret
aes_key = derive_aes_key(shared_secret_sender)

# User input for message
message = st.text_input("Enter message: ")

# Encrypt the message with AES
if message:
    encrypted_message, tag = encrypt_message(aes_key, message)
    st.write(f"Encrypted message: {encrypted_message}")

    # Decrypt the message back to verify
    decrypted_message = decrypt_message(aes_key, encrypted_message, tag)
    st.write(f"Decrypted message: {decrypted_message}")
