
import paho.mqtt.client as mqtt
import argparse
import time
import string
import secrets
import json
from cryptography import x509
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64


# Function to decrypt received message
def aes_decrypt(key: bytes, aad: bytes, nonce_b64: str, enc_b64: str) -> str:
    nonce = base64.b64decode(nonce_b64)
    encrypt_bytes = base64.b64decode(enc_b64)  
    decrypt_bytes = AESGCM(key).decrypt(nonce, encrypt_bytes, aad) 
    return decrypt_bytes.decode()  

# Function to convert certificate to Python object
def load_certificate_object(path: str):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

# function to convert Private key to Python object
def load_private_key_object(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    
# Function to import certificates from Certificate Folder
def import_certificate(folder="Certificates"):
    cert_path = None
    key_path = None

    for file in os.listdir(folder):
        if file.endswith(".crt"):
            cert_path = os.path.join(folder, file)
        elif file.endswith(".key"):
            key_path = os.path.join(folder, file)

    if not cert_path or not key_path:
        raise ValueError("Certificaat of key niet gevonden")

    cert = load_certificate_object(cert_path)
    private_key = load_private_key_object(key_path)

    return cert, private_key

# Function to import certificates as text

def get_certificate_text(folder="Certificates"):
    cert_path = None

    for file in os.listdir(folder):
        if file.lower().endswith(".crt"):
            cert_path = os.path.join(folder, file)
            break

    if cert_path is None:
        raise ValueError("Geen certificaatbestand gevonden")

    with open(cert_path, "r") as f:
        return f.read()
    
# Read member fodler >> WIP Maybe. een andere manier om dit te controleren
def load_member_certificates(folder="NewsTeamJournal Members"):
    trusted = {}

    if not os.path.exists(folder):
        return trusted

    for file in os.listdir(folder):
        if file.lower().endswith(".crt"):
            path = os.path.join(folder, file)
            cert = x509.load_pem_x509_certificate(open(path, "rb").read())
            name = os.path.splitext(file)[0]
            trusted[name] = cert

    return trusted


print("Trusted members loaded:", trusted_certs.keys())

cert, private_key = import_certificate("Certificates")
print("Own certificate loaded:", cert.subject)
print("Private key loaded:", type(private_key))