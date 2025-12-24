import base64
import io
import json
import os
import streamlit as st

from pathlib import Path

from src.auth.registration import RegistrationManager
from src.auth.login import LoginManager
from src.auth.totp import TOTPManager
from src.auth.session import SessionManager

st.set_page_config(page_title="CryptoVault UI", layout="centered")
st.title("CryptoVault – UI Console")

# Sidebar: configuration
st.sidebar.header("Config")
user_db = st.sidebar.text_input("User DB path", value="users.json")
key_store = st.sidebar.text_input("Key store dir", value="keys")
if not user_db:
    st.stop()

# Helpers to get managers
@st.cache_resource
def get_managers(db_path: str):
    return (
        RegistrationManager(db_path),
        LoginManager(db_path),
        TOTPManager(db_path),
        SessionManager(),
    )

reg_mgr, login_mgr, totp_mgr, sess_mgr = get_managers(user_db)

# Tabs for flows
tab_register, tab_login, tab_totp, tab_sessions, tab_msg, tab_files, tab_blockchain = st.tabs([
    "Register",
    "Login",
    "TOTP",
    "Sessions",
    "Messaging",
    "Files",
    "Blockchain",
])

with tab_register:
    st.subheader("Register User")
    username = st.text_input("Username")
    email = st.text_input("Email", value="")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        ok, msg = reg_mgr.register(username.strip(), password, email)
        if ok:
            st.success(msg)
        else:
            st.error(msg)

with tab_login:
    st.subheader("Login")
    username = st.text_input("Username", key="login_user")
    password = st.text_input("Password", type="password", key="login_pass")
    totp_code = st.text_input("TOTP code (if enabled)", key="login_totp")
    backup_code = st.text_input("Backup code (alternative)", key="login_backup")
    ttl = st.number_input("Session TTL (seconds)", min_value=60, max_value=86400, value=3600)
    if st.button("Login & Issue Session Token"):
        ok, msg = login_mgr.login(username.strip(), password)
        if not ok:
            st.error(msg)
        else:
            user = totp_mgr.users.get(username.strip(), {})
            if user.get("totp_enabled"):
                if totp_code:
                    ok, msg = totp_mgr.verify_totp(username.strip(), totp_code)
                elif backup_code:
                    ok, msg = totp_mgr.verify_backup_code(username.strip(), backup_code)
                else:
                    ok = False
                    msg = "TOTP or backup code required"
                if not ok:
                    st.error(msg)
                    st.stop()
            login_mgr.update_last_login(username.strip())
            token = login_mgr.issue_session_token(username.strip(), ttl_seconds=int(ttl))
            st.success("Authenticated. Session token issued:")
            st.code(token)

with tab_totp:
    st.subheader("Enable TOTP")
    username = st.text_input("Username", key="totp_user")
    if st.button("Generate Secret & Enable"):
        if username.strip() not in totp_mgr.users:
            st.error("User not found. Register first.")
        else:
            secret, uri = totp_mgr.generate_secret(username.strip())
            ok, msg = totp_mgr.enable_totp(username.strip(), secret)
            if not ok:
                st.error(msg)
            else:
                st.success("TOTP enabled. Add to your authenticator.")
                st.write(f"Secret: {secret}")
                st.write(f"URI: {uri}")
                # Show QR code image from base64
                from src.auth.totp import TOTPManager as _TM
                qr_b64 = totp_mgr.get_qr_code(uri)
                st.image(base64.b64decode(qr_b64), caption="Scan in authenticator app")
                # Show plaintext backup codes (ephemeral)
                ok_codes, codes = totp_mgr.get_last_generated_backup_codes(username.strip())
                if ok_codes:
                    st.write("Backup codes (store securely):")
                    st.code("\n".join(codes))
    st.divider()
    st.subheader("Show Backup Codes")
    username2 = st.text_input("Username", key="totp_user2")
    if st.button("Show Stored Backup Codes"):
        ok, codes = totp_mgr.get_backup_codes(username2.strip())
        if ok:
            st.write("Stored hashed backup codes:")
            st.code("\n".join(codes))
        else:
            st.error("User not found")

with tab_sessions:
    st.subheader("Validate / Revoke Session")
    token = st.text_input("Token")
    cols = st.columns(2)
    with cols[0]:
        if st.button("Validate"):
            st.write("Valid:" if sess_mgr.validate(token) else "Invalid")
    with cols[1]:
        if st.button("Revoke"):
            sess_mgr.revoke(token)
            st.success("Revoked (if existed)")

with tab_msg:
    st.subheader("Messaging – Keys & Envelopes")
    from src.keystore.fs_store import (
        ensure_store,
        list_keys,
        save_private_key,
        save_public_key,
        load_private_key,
        load_public_key,
    )
    from src.messaging.key_exchange import generate_ec_keypair
    from src.messaging.schema import (
        create_envelope,
        create_envelope_ephemeral,
        envelope_to_json,
        verify_and_decrypt_envelope,
    )

    ensure_store(key_store)
    st.markdown("### Generate EC Keypair")
    new_label = st.text_input("Label", key="gen_label")
    if st.button("Generate Keys"):
        if not new_label.strip():
            st.error("Label required")
        else:
            priv, pub = generate_ec_keypair()
            p1 = save_private_key(new_label.strip(), priv, base_dir=key_store)
            p2 = save_public_key(new_label.strip(), pub, base_dir=key_store)
            st.success(f"Generated: {p1}, {p2}")

    st.markdown("### Send Message")
    # Convert filenames in keystore to logical labels
    pem_files = list(list_keys(base_dir=key_store))
    labels = set()
    for fname in pem_files:
        if fname.endswith("_private.pem"):
            labels.add(fname[:-12])  # strip _private.pem
        elif fname.endswith("_public.pem"):
            labels.add(fname[:-11])  # strip _public.pem
    all_labels = sorted(labels)
    if not all_labels:
        st.info("No keys yet. Generate at least two labels.")
    sender_label = st.selectbox("Sender label (signing + ECDH)", all_labels, key="sender_label")
    recipient_label = st.selectbox("Recipient label", all_labels, key="recipient_label")
    msg_text = st.text_area("Message", value="Hello, secure world!", height=120)
    use_ephemeral = st.checkbox("Use ephemeral ECDH (PFS)", value=True)
    if st.button("Create Envelope"):
        if not sender_label or not recipient_label:
            st.error("Select sender and recipient labels")
        else:
            # Normalize labels (in case Streamlit cached an old '.pem' filename)
            def _normalize(lbl: str) -> str:
                if lbl.endswith("_private.pem"):
                    return lbl[:-12]
                if lbl.endswith("_public.pem"):
                    return lbl[:-11]
                return lbl
            sender_priv = load_private_key(_normalize(sender_label), base_dir=key_store)
            recipient_pub = load_public_key(_normalize(recipient_label), base_dir=key_store)
            if use_ephemeral:
                env = create_envelope_ephemeral(msg_text.encode("utf-8"), sender_priv, recipient_pub)
            else:
                env = create_envelope(msg_text.encode("utf-8"), sender_priv, recipient_pub)
            st.success("Envelope created")
            st.code(envelope_to_json(env), language="json")

    st.markdown("### Receive Message")
    recv_label = st.selectbox("Recipient label (to decrypt)", all_labels, key="recv_label")
    env_json = st.text_area("Envelope JSON", height=200)
    if st.button("Verify & Decrypt"):
        try:
            def _normalize(lbl: str) -> str:
                if lbl.endswith("_private.pem"):
                    return lbl[:-12]
                if lbl.endswith("_public.pem"):
                    return lbl[:-11]
                return lbl
            recipient_priv = load_private_key(_normalize(recv_label), base_dir=key_store)
            out = verify_and_decrypt_envelope(env_json, recipient_priv)
            st.success("Verified and decrypted")
            st.code(out.decode("utf-8", errors="replace"))
        except Exception as e:
            st.error(f"Failed: {e}")

with tab_files:
    st.subheader("File Encryption – Password-Based")
    from src.files.secure import encrypt_file_pw, decrypt_file_pw

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Encrypt File")
        input_file = st.text_input("Input file path", key="enc_input")
        output_file = st.text_input("Output file path (*.sec)", key="enc_output")
        password = st.text_input("Password", type="password", key="enc_pass")
        pbkdf2_iters = st.number_input(
            "PBKDF2 iterations", min_value=100_000, max_value=1_000_000, value=200_000, step=10_000
        )
        if st.button("Encrypt"):
            if not all([input_file, output_file, password]):
                st.error("All fields required")
            else:
                try:
                    from pathlib import Path
                    if not Path(input_file).exists():
                        st.error(f"{input_file} not found")
                    else:
                        meta = encrypt_file_pw(
                            input_file, output_file, password, pbkdf2_iters=int(pbkdf2_iters)
                        )
                        st.success(f"Encrypted. Original SHA-256: {meta['original_sha256']}")
                        st.code(f"File: {output_file}")
                except Exception as e:
                    st.error(f"Encrypt failed: {e}")

    with col2:
        st.markdown("### Decrypt File")
        input_enc = st.text_input("Encrypted file path", key="dec_input")
        output_dec = st.text_input("Output file path", key="dec_output")
        password_dec = st.text_input("Password", type="password", key="dec_pass")
        if st.button("Decrypt"):
            if not all([input_enc, output_dec, password_dec]):
                st.error("All fields required")
            else:
                try:
                    from pathlib import Path
                    if not Path(input_enc).exists():
                        st.error(f"{input_enc} not found")
                    else:
                        meta = decrypt_file_pw(input_enc, output_dec, password_dec)
                        st.success(f"Decrypted. Original SHA-256: {meta['original_sha256']}")
                        st.code(f"File: {output_dec}")
                except ValueError as e:
                    if "HMAC" in str(e):
                        st.error(f"⚠️ Tamper detected: {e}")
                    else:
                        st.error(f"Decrypt failed: {e}")
                except Exception as e:
                    st.error(f"Decrypt failed: {e}")

with tab_blockchain:
    st.subheader("Blockchain – Audit Ledger")
    from src.blockchain.ledger import Blockchain
    from pathlib import Path

    chain_path = st.text_input("Chain file path", value="chain.json")
    if not chain_path:
        st.stop()

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Chain Info")
        if st.button("Load & Show Info"):
            try:
                if Path(chain_path).exists():
                    chain = Blockchain.load(chain_path)
                    st.write(f"Height: {chain.height}")
                    st.write(f"Head hash: {chain.head.hash}")
                    st.write(f"Cumulative work: {chain.cumulative_work()}")
                    st.write(f"Is valid: {chain.is_valid()}")
                else:
                    st.info("Chain file does not exist. Add a block to create it.")
            except Exception as e:
                st.error(f"Failed: {e}")

    with col2:
        st.markdown("### Add Block")
        data_input = st.text_area("Transaction data (comma-separated)", value="tx1,tx2", height=60)
        default_diff = st.number_input("Difficulty", min_value=4, max_value=20, value=12)
        if st.button("Add Block"):
            try:
                txs = [t.strip() for t in data_input.split(",") if t.strip()]
                if not txs:
                    st.error("No transactions")
                else:
                    if Path(chain_path).exists():
                        chain = Blockchain.load(chain_path)
                    else:
                        chain = Blockchain(default_difficulty=default_diff)
                    blk = chain.add_block(txs)
                    chain.save(chain_path)
                    st.success(f"Added block {blk.index} with hash {blk.hash[:16]}...")
            except Exception as e:
                st.error(f"Failed: {e}")

    st.divider()
    st.markdown("### Audit Log")
    action = st.text_input("Audit action", value="file_upload")
    user = st.text_input("User", value="system")
    if st.button("Append Audit"):
        try:
            if Path(chain_path).exists():
                chain = Blockchain.load(chain_path)
            else:
                chain = Blockchain()
            chain.append_audit(action, user=user)
            chain.save(chain_path)
            proof = chain.audit_proof()
            st.success("Audit entry appended")
            st.code(proof, language="text")
        except Exception as e:
            st.error(f"Failed: {e}")
