# Secure MQTT Chat

## Project overview
This project implements a secure group chat application using MQTT and Python.  
It ensures that only trusted participants can read and send messages by applying cryptography at the application layer.

---

## Features
- Encrypted group communication (AES-GCM)
- Certificate-based identity verification
- Digital signatures for authentication
- Secure group key distribution (RSA)
- Trusted member validation

---

## Key components
- `aes_encrypt / aes_decrypt` → message encryption  
- `encrypt_groupchat_key / decrypt_groupchat_key` → secure key exchange  
- `sign_data / verify_data` → authentication  
- `load_members / is_member` → trust management  

---

## File structure
- `info_chat.py` – main application  
- `NTJkey.bin` – group key  
- `Personal ID/` – certificate & private key  
- `NewsTeamJournal Members/` – trusted users  

---

## Requirements
```bash
python3 -m pip install -r requirements.txt