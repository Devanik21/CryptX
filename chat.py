import streamlit as st
import base64
import os
import io
import json
import qrcode
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, eddsa
from Crypto.Hash import SHA256, SHA3_256, HMAC
from Crypto.Protocol.KDF import PBKDF2, scrypt
import google.generativeai as genai
import pandas as pd
import matplotlib.pyplot as plt

# --- Streamlit UI ---
st.set_page_config("CryptX ", layout="wide",page_icon="🔐")
st.title("🛡️ CryptX Vault Pro – Advanced Cryptography Suite")

# --- Gemini Key ---
api_key = st.sidebar.text_input("🔑 Enter Gemini API Key", type="password")
if api_key:
    genai.configure(api_key=api_key)
    gemini_model = genai.GenerativeModel("gemini-2.0-flash")

# --- Modern UI with SelectBox instead of tabs ---
feature = st.sidebar.selectbox(
    "Select Feature",
    ["🔐 AES Encrypt/Decrypt", 
     "🌀 ChaCha20 Encrypt/Decrypt",
     "🔏 Asymmetric Cryptography", 
     "📜 HMAC & Hash Functions", 
     "🤖 AI Code Explainer",
     "🔑 Password Strength Analyzer",
     "📊 Encryption Benchmark",
     "📱 QR Code Generator",
     "🔄 Format Converter"]
)

# --- 1. AES Encrypt/Decrypt ---
if feature == "🔐 AES Encrypt/Decrypt":
    st.header("🔐 AES File Encryption / Decryption")
    
    # New addition: KDF options
    kdf_options = st.selectbox("Key Derivation Function", ["PBKDF2", "Scrypt"])
    
    aes_mode = st.radio("Mode", ["Encrypt", "Decrypt"])
    uploaded_file = st.file_uploader("Choose a file")

    password = st.text_input("Password", type="password")
    salt = get_random_bytes(16) if aes_mode == "Encrypt" else None
    
    # Advanced options
    with st.expander("Advanced Options"):
        iterations = st.slider("KDF Iterations", 10000, 1000000, 100000)
    
    aes_btn = st.button("Run AES")

    if uploaded_file and password and aes_btn:
        data = uploaded_file.read()
        
        # Apply selected KDF
        if kdf_options == "PBKDF2":
            key = PBKDF2(password.encode(), salt if salt else data[:16], dkLen=32, count=iterations)
        else:  # Scrypt
            key = scrypt(password.encode(), salt if salt else data[:16], key_len=32, N=2**14, r=8, p=1)
            
        cipher = AES.new(key, AES.MODE_EAX)

        if aes_mode == "Encrypt":
            ciphertext, tag = cipher.encrypt_and_digest(data)
            output = salt + cipher.nonce + tag + ciphertext
            st.download_button("Download Encrypted File", output, file_name="encrypted.bin")
            
            # Security info
            st.info(f"✅ File encrypted with {len(key)*8} bit key, {kdf_options} with {iterations} iterations")
        else:
            try:
                salt, nonce, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]
                cipher = AES.new(key, AES.MODE_EAX, nonce)
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                
                # Try to detect file type
                file_ext = "bin"
                if decrypted.startswith(b'%PDF'):
                    file_ext = "pdf"
                elif decrypted.startswith(b'\xff\xd8\xff'):
                    file_ext = "jpg"
                elif decrypted.startswith(b'PK'):
                    file_ext = "zip"
                
                st.download_button("Download Decrypted File", decrypted, file_name=f"decrypted.{file_ext}")
            except Exception as e:
                st.error(f"❌ Decryption Failed – {str(e)}")

# --- 2. ChaCha20 Encrypt/Decrypt (NEW FEATURE) ---
elif feature == "🌀 ChaCha20 Encrypt/Decrypt":
    st.header("🌀 ChaCha20-Poly1305 Encryption")
    st.markdown("Modern, high-performance encryption algorithm")
    
    chacha_mode = st.radio("Mode", ["Encrypt", "Decrypt"])
    uploaded_file = st.file_uploader("Choose a file")

    password = st.text_input("Password", type="password")
    chacha_btn = st.button("Process")

    if uploaded_file and password and chacha_btn:
        data = uploaded_file.read()
        key = SHA256.new(password.encode()).digest()
        
        if chacha_mode == "Encrypt":
            nonce = get_random_bytes(12)  # 96 bits
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            output = nonce + tag + ciphertext
            st.download_button("Download Encrypted File", output, file_name="chacha_encrypted.bin")
            st.success("File encrypted with ChaCha20-Poly1305")
        else:
            try:
                nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
                cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                st.download_button("Download Decrypted File", decrypted, file_name="chacha_decrypted.bin")
            except Exception as e:
                st.error(f"❌ ChaCha20 Decryption Failed – {str(e)}")

# --- 3. RSA/ECC/EdDSA Playground ---
elif feature == "🔏 Asymmetric Cryptography":
    st.header("🔏 Key Generation + Signature Verification")
    crypto_type = st.selectbox("Choose Crypto System", ["RSA", "ECC", "EdDSA"])

    message = st.text_area("Message to Sign")
    
    # Add option to save keys
    save_keys = st.checkbox("Save keys to file")
    
    if st.button("Generate Keys + Sign"):
        if crypto_type == "RSA":
            # Let user choose key size
            key_size = st.select_slider("RSA Key Size (bits)", options=[1024, 2048, 3072, 4096], value=2048)
            
            rsa_key = RSA.generate(key_size)
            h = SHA256.new(message.encode())
            sig = pkcs1_15.new(rsa_key).sign(h)
            
            # Display in more organized way
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Private Key")
                st.code(rsa_key.export_key().decode(), language="pem")
                if save_keys:
                    st.download_button("Download Private Key", rsa_key.export_key(), file_name="private_key.pem")
            
            with col2:
                st.subheader("Public Key")
                st.code(rsa_key.publickey().export_key().decode(), language="pem")
                if save_keys:
                    st.download_button("Download Public Key", rsa_key.publickey().export_key(), file_name="public_key.pem")
            
            st.subheader("Signature")
            st.code(sig.hex(), language="bash")
            st.download_button("Download Signature", sig, file_name="signature.bin")

        elif crypto_type == "ECC":
            ecc_key = ECC.generate(curve='P-256')
            h = SHA256.new(message.encode())
            signer = ecc_key.sign(h)
            
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Private Key")
                st.code(ecc_key.export_key(format='PEM'), language="pem")
                if save_keys:
                    st.download_button("Download ECC Private Key", ecc_key.export_key(format='PEM'), file_name="ecc_private.pem")
            
            with col2:
                st.subheader("Public Key")
                public_key = ecc_key.public_key().export_key(format='PEM')
                st.code(public_key, language="pem")
                if save_keys:
                    st.download_button("Download ECC Public Key", public_key, file_name="ecc_public.pem")
            
            st.subheader("Signature")
            st.write("Signature:", signer.hex())

        elif crypto_type == "EdDSA":
            ed_key = ECC.generate(curve='Ed25519')
            h = SHA256.new(message.encode())
            signer = eddsa.new(ed_key, 'rfc8032')
            signature = signer.sign(h)
            
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Private Key")
                st.code(ed_key.export_key(format='PEM'), language="pem")
                if save_keys:
                    st.download_button("Download EdDSA Private Key", ed_key.export_key(format='PEM'), file_name="eddsa_private.pem")
            
            st.subheader("Signature")
            st.write("Signature (hex):", signature.hex())
            st.download_button("Download EdDSA Signature", signature, file_name="eddsa_sig.bin")

# --- 4. HMAC & Hash Functions (Enhanced) ---
elif feature == "📜 HMAC & Hash Functions":
    st.header("📜 Hash Functions & HMAC Generator")
    
    hash_tab, hmac_tab = st.tabs(["Hash Functions", "HMAC"])
    
    with hash_tab:
        hash_algo = st.selectbox("Hash Algorithm", ["SHA-256", "SHA3-256"])
        hash_input = st.text_area("Text to Hash")
        
        if st.button("Generate Hash"):
            if hash_algo == "SHA-256":
                h = SHA256.new(hash_input.encode())
            else:  # SHA3-256
                h = SHA3_256.new(hash_input.encode())
            
            st.code(h.hexdigest(), language="bash")
    
    with hmac_tab:
        hmac_key = st.text_input("Secret Key")
        hmac_msg = st.text_area("Message")

        if st.button("Generate HMAC"):
            h = HMAC.new(hmac_key.encode(), digestmod=SHA256)
            h.update(hmac_msg.encode())
            st.code(h.hexdigest(), language="bash")

# --- 5. Gemini-Powered Code Explain ---
elif feature == "🤖 AI Code Explainer":
    st.header("🤖 Gemini-Powered Code Explainer")
    code_input = st.text_area("Paste Code to Explain", height=250)
    
    # Add option to select detail level
    detail_level = st.select_slider(
        "Detail Level", 
        options=["Basic", "Standard", "Detailed"], 
        value="Standard"
    )

    if st.button("Explain Code with Gemini"):
        if api_key and code_input.strip():
            with st.spinner("Explaining with Gemini..."):
                detail_instructions = {
                    "Basic": "Give a simple overview of what this code does:",
                    "Standard": "Explain what this code does in detail:",
                    "Detailed": "Provide an in-depth explanation of this code with security considerations and suggestions for improvement:"
                }
                
                explain_prompt = f"{detail_instructions[detail_level]}\n\n{code_input}"
                try:
                    resp = gemini_model.generate_content(explain_prompt)
                    st.success("✅ Explanation:")
                    st.markdown(resp.text)
                except Exception as e:
                    st.error(f"Error: {str(e)}")
        else:
            st.warning("Please enter your Gemini API Key and code.")

# --- 6. Password Strength Analyzer (NEW FEATURE) ---
elif feature == "🔑 Password Strength Analyzer":
    st.header("🔑 Password Strength Analyzer")
    
    password = st.text_input("Enter Password to Analyze", type="password")
    
    if password:
        # Calculate password strength
        score = 0
        feedback = []
        
        # Length check
        if len(password) < 8:
            feedback.append("❌ Password is too short (less than 8 characters)")
        elif len(password) >= 12:
            score += 2
            feedback.append("✅ Good length (12+ characters)")
        else:
            score += 1
            feedback.append("⚠️ Acceptable length (8-11 characters)")
        
        # Complexity checks
        if any(char.isupper() for char in password):
            score += 1
            feedback.append("✅ Contains uppercase letters")
        else:
            feedback.append("❌ No uppercase letters")
            
        if any(char.islower() for char in password):
            score += 1
            feedback.append("✅ Contains lowercase letters")
        else:
            feedback.append("❌ No lowercase letters")
            
        if any(char.isdigit() for char in password):
            score += 1
            feedback.append("✅ Contains numbers")
        else:
            feedback.append("❌ No numbers")
            
        if any(not char.isalnum() for char in password):
            score += 2
            feedback.append("✅ Contains special characters")
        else:
            feedback.append("❌ No special characters")
        
        # Check for common patterns
        common_patterns = ['123456', 'password', 'qwerty', 'admin']
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 2
            feedback.append("❌ Contains common patterns")
            
        # Display results
        strength_labels = {
            0: "Very Weak", 
            1: "Very Weak", 
            2: "Weak", 
            3: "Moderate", 
            4: "Moderate", 
            5: "Strong", 
            6: "Strong",
            7: "Very Strong"
        }
        
        # Clamp score between 0-7
        score = max(0, min(score, 7))
        
        # Display strength gauge
        st.subheader(f"Password Strength: {strength_labels[score]}")
        st.progress(score/7)
        
        # Colored strength indicator
        colors = {
            "Very Weak": "red",
            "Weak": "orange",
            "Moderate": "blue",
            "Strong": "green",
            "Very Strong": "green"
        }
        
        st.markdown(f"<h3 style='color: {colors[strength_labels[score]]};'>{strength_labels[score]}</h3>", unsafe_allow_html=True)
        
        # Feedback
        st.subheader("Analysis:")
        for item in feedback:
            st.markdown(item)
            
        # Time to crack estimate (very simplified)
        crack_times = {
            0: "Instantly",
            1: "Instantly",
            2: "Minutes to hours",
            3: "Hours to days",
            4: "Days to weeks",
            5: "Weeks to months",
            6: "Months to years",
            7: "Many years"
        }
        
        st.subheader("Estimated time to crack:")
        st.info(crack_times[score])

# --- 7. Encryption Benchmark (NEW FEATURE) ---
elif feature == "📊 Encryption Benchmark":
    st.header("📊 Encryption Algorithm Benchmark")
    
    # Sample benchmark data
    benchmark_data = {
        "Algorithm": ["AES-256-GCM", "ChaCha20-Poly1305", "AES-128-GCM", "3DES", "Blowfish"],
        "Speed (MB/s)": [950, 1350, 1100, 65, 372],
        "Security Level": ["Very High", "Very High", "High", "Medium", "High"]
    }
    
    df = pd.DataFrame(benchmark_data)
    
    # Display as table
    st.subheader("Performance Comparison")
    st.dataframe(df)
    
    # Create visualization
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(df["Algorithm"], df["Speed (MB/s)"], color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd'])
    ax.set_title("Encryption Algorithm Performance")
    ax.set_xlabel("Algorithm")
    ax.set_ylabel("Speed (MB/s)")
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')
    
    st.pyplot(fig)
    
    # Security recommendations
    st.subheader("Security Recommendations")
    st.info("For most modern applications, AES-256-GCM and ChaCha20-Poly1305 offer the best combination of security and performance.")
    
    with st.expander("Algorithm Details"):
        st.markdown("""
        - **AES-256-GCM**: Industry standard, hardware accelerated on most modern CPUs
        - **ChaCha20-Poly1305**: Excellent for software implementations, preferred for mobile
        - **AES-128-GCM**: Still secure but with a smaller key size than AES-256
        - **3DES**: Legacy algorithm, much slower than modern options
        - **Blowfish**: Older algorithm with decent performance but not recommended for new applications
        """)

# --- 8. QR Code Generator (NEW FEATURE) ---
elif feature == "📱 QR Code Generator":
    st.header("📱 Secure QR Code Generator")
    
    qr_data = st.text_area("Enter data for QR code", placeholder="Text, URL, or encrypted data")
    qr_size = st.slider("QR Code Size", 1, 10, 5)
    
    # Security options
    with st.expander("Security Options"):
        st.warning("For sensitive data, consider encrypting before generating QR code")
        encrypt_data = st.checkbox("Encrypt with password")
        
        if encrypt_data:
            qr_password = st.text_input("Encryption password", type="password")
    
    if st.button("Generate QR Code"):
        if qr_data:
            # Optional encryption
            final_data = qr_data
            if encrypt_data and qr_password:
                # Simple encryption for QR data
                key = SHA256.new(qr_password.encode()).digest()
                cipher = AES.new(key, AES.MODE_EAX)
                encrypted_data, tag = cipher.encrypt_and_digest(qr_data.encode())
                
                # Format as JSON for easier decoding
                metadata = {
                    "encrypted": True,
                    "nonce": base64.b64encode(cipher.nonce).decode('ascii'),
                    "tag": base64.b64encode(tag).decode('ascii'),
                    "data": base64.b64encode(encrypted_data).decode('ascii')
                }
                final_data = json.dumps(metadata)
                st.info("Data encrypted in QR code. Share the password separately.")
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=qr_size,
                border=4,
            )
            qr.add_data(final_data)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to bytes for display
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            img_bytes = img_bytes.getvalue()
            
            # Display and download
            st.image(img_bytes, caption="Generated QR Code")
            st.download_button(
                label="Download QR Code",
                data=img_bytes,
                file_name="qrcode.png",
                mime="image/png"
            )

# --- 9. Format Converter (NEW FEATURE) ---
elif feature == "🔄 Format Converter":
    st.header("🔄 Cryptographic Format Converter")
    
    conversion_type = st.selectbox(
        "Choose Conversion", 
        ["Base64 Encode/Decode", 
         "Hex Encode/Decode", 
         "PEM to DER",
         "ASCII to Binary"]
    )
    
    input_data = st.text_area("Input Data")
    
    if conversion_type == "Base64 Encode/Decode":
        mode = st.radio("Mode", ["Encode", "Decode"])
        
        if st.button("Convert"):
            if input_data:
                if mode == "Encode":
                    result = base64.b64encode(input_data.encode()).decode()
                    st.code(result)
                else:
                    try:
                        result = base64.b64decode(input_data).decode()
                        st.code(result)
                    except Exception as e:
                        st.error(f"Decoding error: {str(e)}")
    
    elif conversion_type == "Hex Encode/Decode":
        mode = st.radio("Mode", ["Encode", "Decode"])
        
        if st.button("Convert"):
            if input_data:
                if mode == "Encode":
                    result = input_data.encode().hex()
                    st.code(result)
                else:
                    try:
                        result = bytes.fromhex(input_data).decode()
                        st.code(result)
                    except Exception as e:
                        st.error(f"Hex decoding error: {str(e)}")
    
    elif conversion_type == "PEM to DER":
        mode = st.radio("Mode", ["PEM to DER", "DER to PEM"])
        key_type = st.selectbox("Key Type", ["RSA", "ECC"])
        
        if st.button("Convert"):
            st.warning("For a complete implementation, use the appropriate functions from PyCryptodome to handle various key formats")
            st.info("This would convert between PEM (text-based) and DER (binary) formats of cryptographic keys")
    
    elif conversion_type == "ASCII to Binary":
        mode = st.radio("Mode", ["ASCII to Binary", "Binary to ASCII"])
        
        if st.button("Convert"):
            if input_data and mode == "ASCII to Binary":
                result = ' '.join(format(ord(char), '08b') for char in input_data)
                st.code(result)
            elif input_data and mode == "Binary to ASCII":
                try:
                    binary_values = input_data.split()
                    result = ''.join(chr(int(binary, 2)) for binary in binary_values)
                    st.code(result)
                except Exception as e:
                    st.error(f"Conversion error: {str(e)}")

st.markdown("---")
st.caption("Built with ❤️ using PyCryptodome, Streamlit, and Gemini AI.")
