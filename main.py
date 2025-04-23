import streamlit as st   # for using url/live.
import hashlib           # Password Hashing: Passwords ko hash karna, taake woh securely store kiya ja sake.
import json              # File Handling: JSON files ko read ya write karne ke liye.
import time              # Performance Measurement, Delays in Execution: Code execution me delay introduce karne ke liye.
import os                # Path Operations, System Information, Process Management.
from cryptography.fernet import Fernet   # Data Encryption, Data Decryption, Secure Communication, Key Generation.
from base64 import urlsafe_b64encode    # base64 module is used for Base64 encoding, Generating Safe Tokens, Secure Data Handling.
from hashlib import pbkdf2_hmac     # Hash-based Message Authentication Code.



# ********* For User information ********* .


Data_File = "secure_data.json"  # JSON file ka naam jisme user data store hoga.
Salt =  b"secure_salt_value"  # Salt value jo password hashing ke liye use hoti hai.
Lockout_Duration = 60  # seconds, Agar user 3 baar galat password enter kare to woh kitne der ke liye lock hoga.
Max_Attempts = 3  # Maximum attempts before lockout.

# For Login 

if "authenticated_user" not in st.session_state: # for login
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:    # login failed
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0            # for lockout time



# Functions for data  read & write, genrate pass keys, data encryption & decryption.:

def load_data():  
    if os.path.exists(Data_File):    
        with open(Data_File, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(Data_File, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    # Derive a key using PBKDF2
    key = pbkdf2_hmac('sha256', passkey.encode(), Salt, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), Salt, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None
    



    # === Load stored data from JSON ===
stored_data = load_data()

# === Navigation bar  ===
st.title("🔏 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)



import streamlit as st

# Home Page
if choice == "Home":
    # Hero Section
    st.subheader("🏠 Welcome to DataVault!")
    st.markdown("""
         Use this app to **securely store and retrieve data** using unique passkeys..
                
        🔒 **Store data securely.**  
        🔑 **Retrieve with unique passkeys.**  
        🚀 **Get started today!**
    """)

   
# *** Register ***

elif choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("Both fields are required.")



# *** for Login ***

elif choice == "Login":
    st.subheader("🔑 User Login")
    
    # Lockout check
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials! Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + Lockout_Duration
                st.error("🔒 Too many failed attempts. Locked for 60 seconds.")
                st.stop()








# *** Store Data ***
#                 
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption Key (passphrase)", type="password")

        if st.button("Encrypt & Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved!")
            else:
                st.error("All fields are required.")



# *** Retrieve Data ***

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("🔎 Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No data found.")
        else:
            st.write("🔐 Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("Enter Encrypted Text")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"✅ Decrypted: {result}")
                else:
                    st.error("❌ Incorrect passkey or corrupted data.")