import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ---------- 0. ONE-TIME INITIALISATION ----------
if "cipher" not in st.session_state:
    KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(KEY)
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

cipher = st.session_state.cipher
stored_data = st.session_state.stored_data


# ---------- 1. HELPERS ----------
def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()


def encrypt_data(plaintext: str) -> str:
    return cipher.encrypt(plaintext.encode()).decode()


def decrypt_data(enc_text: str, passkey: str) -> str | None:
    hashed = hash_passkey(passkey)
    data = stored_data.get(enc_text)
    if data and data["pass"] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(enc_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None


# ---------- 2. CUSTOM STYLES ----------
st.markdown("""
    <style>
        .main {
            background-color: #fdfcfb;
            font-family: 'Segoe UI', sans-serif;
        }
        .block-container {
            padding-top: 2rem;
        }
        .stTextInput > div > div > input {
            border-radius: 0.5rem;
            padding: 0.6rem;
            border: 1px solid #ccc;
        }
        .stTextArea > div > textarea {
            border-radius: 0.5rem;
            padding: 0.6rem;
            border: 1px solid #ccc;
        }
        .stButton > button {
            background-color: #2e2e2e;
            color: white;
            padding: 0.5rem 1.2rem;
            border-radius: 8px;
            font-size: 1rem;
            border: none;
        }
        .stButton > button:hover {
            background-color: #444;
        }
    </style>
""", unsafe_allow_html=True)


# ---------- 3. UI ----------
st.title("🌟 SecureVault: Luxe Data Locker")

menu = ["🏠 Home", "🔐 Store Data", "🔓 Retrieve Data", "🔑 Login"]
choice = st.sidebar.radio("🌐 Navigate", menu)

# ---- HOME
if choice == "🏠 Home":
    st.subheader("Welcome to your Private Vault 💼")
    st.markdown("""
        This app lets you **securely store** and **retrieve** sensitive information like passwords,
        notes, or keys. <br><br>
        🔒 Data is encrypted using **Fernet symmetric encryption**.<br>
        🗂️ Stored only in-memory — everything disappears when the app reloads.<br>
        💡 Use the sidebar to get started.
    """, unsafe_allow_html=True)

# ---- STORE
elif choice == "🔐 Store Data":
    st.subheader("🔐 Lock it Up")
    with st.form("store_form", clear_on_submit=True):
        st.write("💬 Enter your secret and set a passkey to encrypt it.")
        user_text = st.text_area("✍️ Enter text to encrypt")
        passkey = st.text_input("🔑 Your Secret Passkey", type="password")
        submitted = st.form_submit_button("✨ Encrypt & Store")

    if submitted:
        if user_text and passkey:
            hashed = hash_passkey(passkey)
            enc_text = encrypt_data(user_text)
            stored_data[enc_text] = {"enc": enc_text, "pass": hashed}
            st.success("✅ Secret locked away securely!")
            st.code(enc_text, language="bash")
        else:
            st.error("❌ Both fields are required to continue.")

# ---- RETRIEVE
elif choice == "🔓 Retrieve Data":
    st.subheader("🔓 Unlock a Secret")

    if st.session_state.failed_attempts >= 3:
        st.warning("🚫 Too many failed attempts – please login again.")
        st.switch_page("app.py", anchor="Login")
        st.stop()

    with st.form("retrieve_form"):
        st.write("🔐 Paste the encrypted text and enter your passkey to retrieve the original.")
        enc_text = st.text_area("📄 Encrypted Text")
        passkey = st.text_input("🔑 Passkey", type="password")
        submitted = st.form_submit_button("🔍 Decrypt")

    if submitted:
        if enc_text and passkey:
            result = decrypt_data(enc_text, passkey)
            if result:
                st.success("✅ Successfully Decrypted:")
                st.write(result)
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Wrong key! Attempts left: {remaining}")
        else:
            st.error("❌ Both fields are required.")

# ---- LOGIN
elif choice == "🔑 Login":
    st.subheader("🛡️ Re-authenticate")
    with st.form("login_form"):
        master = st.text_input("🔒 Master Password", type="password")
        submit = st.form_submit_button("🔓 Login")

    if submit:
        if master == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Welcome back, Guardian. Proceed to 'Retrieve Data'.")
        else:
            st.error("⛔ Incorrect password.")
