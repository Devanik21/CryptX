import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes as h
from cryptography.hazmat.primitives import serialization

# Function to generate ECC keys
def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())  # ECC curve
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt message using ECC public key
def encrypt_message(public_key, message):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Function to decrypt message using ECC private key
def decrypt_message(private_key, encrypted_message):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# Main Streamlit App
def main():
    st.title("Encrypted Chat (ECC)")

    # Generate ECC keys (private and public)
    private_key, public_key = generate_ecc_keys()

    # Input for chat message
    user_input = st.text_input("Enter your message:")

    if user_input:
        # Encrypt the message
        encrypted_message = encrypt_message(public_key, user_input)
        st.write("Encrypted Message:")
        st.write(encrypted_message)

        # Decrypt the message
        decrypted_message = decrypt_message(private_key, encrypted_message)
        st.write("Decrypted Message (Chat with self):")
        st.write(decrypted_message)

# Run the app
if __name__ == "__main__":
    main()
