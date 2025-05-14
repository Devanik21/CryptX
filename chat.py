import streamlit as st
import base64
import os
import io
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, eddsa
from Crypto.Hash import SHA256, HMAC
import google.generativeai as genai

# --- Streamlit UI ---
st.set_page_config("🛡️ CryptX Vault", layout="wide")
st.title("🛡️ CryptX Vault – Secure Multi-Utility Cryptography App")

# --- Gemini Key ---
api_key = st.sidebar.text_input("🔑 Enter Gemini API Key", type="password")
if api_key:
    genai.configure(api_key=api_key)
    gemini_model = genai.GenerativeModel("gemini-1.5-flash")

# --- Tabs ---
tabs = st.tabs(["🔐 AES Encrypt/Decrypt", "🔏 RSA & ECC Keys", "📜 HMAC", "🤖 Explain Code"])

# --- 1. AES Encrypt/Decrypt ---
with tabs[0]:
    st.header("🔐 AES File Encryption / Decryption")
    aes_mode = st.radio("Mode", ["Encrypt", "Decrypt"])
    uploaded_file = st.file_uploader("Choose a file")

    password = st.text_input("Password", type="password")
    aes_btn = st.button("Run AES")

    if uploaded_file and password and aes_btn:
        data = uploaded_file.read()
        key = SHA256.new(password.encode()).digest()
        cipher = AES.new(key, AES.MODE_EAX)

        if aes_mode == "Encrypt":
            ciphertext, tag = cipher.encrypt_and_digest(data)
            output = cipher.nonce + tag + ciphertext
            st.download_button("Download Encrypted File", output, file_name="encrypted.bin")
        else:
            try:
                nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
                cipher = AES.new(key, AES.MODE_EAX, nonce)
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                st.download_button("Download Decrypted File", decrypted, file_name="decrypted.txt")
            except:
                st.error("❌ Decryption Failed – Wrong Password or Corrupted File")

# --- 2. RSA/ECC/EdDSA Playground ---
with tabs[1]:
    st.header("🔏 Key Generation + Signature Verification")
    crypto_type = st.selectbox("Choose Crypto System", ["RSA", "ECC", "EdDSA"])

    message = st.text_area("Message to Sign")
    if st.button("Generate Keys + Sign"):
        if crypto_type == "RSA":
            rsa_key = RSA.generate(2048)
            h = SHA256.new(message.encode())
            sig = pkcs1_15.new(rsa_key).sign(h)
            st.code(rsa_key.export_key().decode(), language="pem")
            st.code(sig.hex(), language="bash")

        elif crypto_type == "ECC":
            ecc_key = ECC.generate(curve='P-256')
            h = SHA256.new(message.encode())
            signer = ecc_key.sign(h)
            st.code(ecc_key.export_key(format='PEM'), language="pem")
            st.write("Signature:", signer)

        elif crypto_type == "EdDSA":
            ed_key = ECC.generate(curve='Ed25519')
            h = SHA256.new(message.encode())
            signer = eddsa.new(ed_key, 'rfc8032')
            signature = signer.sign(h)
            st.code(ed_key.export_key(format='PEM'), language="pem")
            st.write("Signature (hex):", signature.hex())

# --- 3. HMAC Generator ---
with tabs[2]:
    st.header("📜 HMAC Generator")
    hmac_key = st.text_input("Secret Key")
    hmac_msg = st.text_area("Message")

    if st.button("Generate HMAC"):
        h = HMAC.new(hmac_key.encode(), digestmod=SHA256)
        h.update(hmac_msg.encode())
        st.code(h.hexdigest(), language="bash")

# --- 4. Gemini-Powered Code Explain ---
with tabs[3]:
    st.header("🤖 Gemini-Powered Code Explainer")
    code_input = st.text_area("Paste Code to Explain", height=250)

    if st.button("Explain Code with Gemini"):
        if api_key and code_input.strip():
            with st.spinner("Explaining with Gemini..."):
                explain_prompt = f"Explain what this code does in detail:\n\n{code_input}"
                try:
                    resp = gemini_model.generate_content(explain_prompt)
                    st.success("✅ Explanation:")
                    st.markdown(resp.text)
                except Exception as e:
                    st.error(f"Error: {str(e)}")
        else:
            st.warning("Please enter your Gemini API Key and code.")

st.markdown("---")
st.caption("Built with ❤️ using PyCryptodome, Streamlit, and Gemini AI.")
