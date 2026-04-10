import paho.mqtt.client as mqtt
import argparse
import time
import string
import secrets
import json
from cryptography import x509
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import base64

# LOCAL KEY, A NEW GROUP CAN BE CREATED BY CHANGING THIS KEY.
GROUPKEY = "NTJkey.bin" 
MAX_CHARS = 250
MEMBER_FOLDER = "NewsTeamJournal Members"
PERSONAL_ID = "Personal ID"
trusted_certs = {}


def arguments():
    # parse arguments
    parser = argparse.ArgumentParser(description='Basic chat application')
    
    # host MQTT server 
    parser.add_argument('--host', help='Hostname of the MQTT service, i.e. test.mosquitto.org', required=False, default="test.mosquitto.org")
    
    # Chat groupname
    parser.add_argument('--topic', help="MQTT chat topic (default '/acchat')", default='/NewTeamJournalists', required=False)
    
    # Name to join the chat
    parser.add_argument('--name', help="MQTT client name (default, a random string)", required=True)
    
    # Debug mode
    parser.add_argument('--debug', '-D', help="Debug mode", action='store_true', required=False)
    return parser.parse_args()


# Function for every message received
def on_message(client, userdata, message):
    # This function only accepts messages that:
    #  can be parsed as JSON
    #  have a 'message' and 'clientid' element
    #  where the clientid is not our clientid (args.name)
    try:
#       if gDbg: print(f"Message: {message.payload}")
        mesg = json.loads(message.payload)
    except json.decoder.JSONDecodeError:
        # ignore messages that are not JSON formatted
        return

    if not 'name' in mesg:
        # ignore messages that do have a name
        return

    if mesg['name'] == args.name:
        # ignore messages sent by myself
        return

    if not 'cmd' in mesg:
        # if a message is not defined with cmd, ignore the message
        return 
    
    # Decrypt incoming messages using the chat key
    if mesg['cmd'] == 'MESG':
        try:
            aad = f"{mesg['topic']}|MESG|{mesg['name']}".encode()

            # Load the shared group key (NTJkey.bin)
            key = load_groupchat_key()
            if key is None:
                if gDbg:
                    print(f"No key yet, ignoring message from {mesg['name']}")
                return

            # Decrypt incoming message
            plaintext = aes_decrypt(
                key,
                aad,
                mesg['nonce'],
                mesg['encrypt_text']
            )

            print(f"{mesg['name']}: {plaintext}")
        except Exception as e:
            
            if gDbg: print(f"Received: '{mesg}'")

    # Verification of the HELO message by certificate and signature
    elif mesg['cmd'] == 'HELO':
        try:
            client_cert = x509.load_pem_x509_certificate(mesg['cert'].encode())
            name = mesg['name']
            print(f"{name} presents a certificate")

            payload = f"{name}|{mesg['topic']}|HELO".encode()

            # Verify the certificate
            if not verify_data(client_cert, payload, mesg['signature']):
                print(f"{name} failed signature check")
                return

            print(f"{name} verified possession of the private key")

            
            temp_user = False

            # Validate if user is a member 
            if not is_member(name, client_cert, trusted_certs):
                print(f"{name} is not trusted yet.")
                decision = input(f"Trust {name}? (yes/no): ").strip().lower()

                if decision != "yes":
                    print(f"{name} rejected")
                    return

                # Grant temporary membership
                trusted_certs[name] = client_cert
                print(f"{name} has been added as temporary member.")
                temp_user = True

            if temp_user or is_member(name, client_cert, trusted_certs):
                chat_key = get_groupchat_key()
                encrypted_key = encrypt_groupchat_key(chat_key, client_cert)

                join_msg = {
                    "cmd": "JOIN",
                    "topic": args.topic,
                    "name": args.name,
                    "target": name,
                    "key": encrypted_key
                }

                client.publish(args.topic, json.dumps(join_msg))
                print(f"Sent group key securely to {name}")

        except Exception as e:
            print(f"ERROR with Certificate: {e}")

    # When accepted by another membersend the group key to the new joiner.

    elif mesg['cmd'] == 'JOIN':
        try:
            if mesg['target'] != args.name:
                return
            
            # 
            _, my_private_key = import_certificate(PERSONAL_ID)
            chat_key = decrypt_groupchat_key(mesg['key'], my_private_key)
            save_groupchat_key(chat_key)

            print(f"You have been admitted by {mesg['name']}. Group key received.")

        except Exception as e:
            print(f"ERROR processing JOIN: {e}")
    

# Student work {{


# Create groupchat key
def get_groupchat_key() -> bytes:
    if os.path.exists(GROUPKEY): #
        with open(GROUPKEY, "rb") as f:
            return f.read()

   # if Key doesn't exists, create a new key.
    key = os.urandom(32)
    with open(GROUPKEY, "wb") as f:
        f.write(key)

    return key

# Encrypt groupchat key which is send to the new joiner
def encrypt_groupchat_key(chat_key: bytes, cert) -> str:
    public_key = cert.public_key()
    encrypted_key = public_key.encrypt(
        chat_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode()

# Decrypt the groupchat key for the new joiner
def decrypt_groupchat_key(encrypted_key_b64: str, private_key) -> bytes:
    encrypted_key = base64.b64decode(encrypted_key_b64)
    chat_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return chat_key

# Save the groupkey file in current folder.
def save_groupchat_key(chat_key: bytes):
    with open(GROUPKEY, "wb") as f:
        f.write(chat_key)

# Load the groupchat key file if it exists.
def load_groupchat_key():
    if os.path.exists(GROUPKEY):
        with open(GROUPKEY, "rb") as f:
            return f.read()
    return None

# Encrypt the messages send in the chat with AES
def aes_encrypt(key: bytes, aad: bytes, plaintext: str) -> dict:
    nonce = os.urandom(12)
    # encrypt the data
    encrypt_text = AESGCM(key).encrypt(nonce, plaintext.encode(), aad)
    return {
        'nonce': base64.b64encode(nonce).decode(),
        'encrypt_text' : base64.b64encode(encrypt_text).decode(),
    }

# Decrypt the messgages in the chat
def aes_decrypt(key: bytes, aad: bytes, nonce_b64: str, enc_b64: str) -> str:
    nonce = base64.b64decode(nonce_b64)
    encrypt_bytes = base64.b64decode(enc_b64)  
    decrypt_bytes = AESGCM(key).decrypt(nonce, encrypt_bytes, aad) 
    return decrypt_bytes.decode()  

# Convert certificate to a PEM file for encryption operations.
def convert_certificate_object(path: str):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

# Convert private key to a PEM file for encryption operations.
def convert_private_key_object(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    
# Read personal certificate and key from the PERSONAL KEY folder.
def import_certificate(folder=PERSONAL_ID):
    cert_path = None
    key_path = None

    for file in os.listdir(folder):
        if file.endswith(".crt"):
            cert_path = os.path.join(folder, file)
        elif file.endswith(".key"):
            key_path = os.path.join(folder, file)

    if not cert_path or not key_path:
        raise ValueError("Certificate or Key has not been found")

    cert = convert_certificate_object(cert_path)
    private_key = convert_private_key_object(key_path)

    return cert, private_key

# Import certificates as text to send with "HELO" message
def get_certificate_text(folder=PERSONAL_ID):
    cert_path = None

    for file in os.listdir(folder):
        if file.lower().endswith(".crt"):
            cert_path = os.path.join(folder, file)
            break

    if cert_path is None:
        raise ValueError("No certificate has been found")

    with open(cert_path, "r") as f:
        return f.read()
    
# Load trusted members in the defined folder
def load_members(folder=MEMBER_FOLDER):
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

# Verify new joiner if they are a member when joining the chat.
def is_member(name: str, incoming_cert, trusted_certs: dict) -> bool:
    if name not in trusted_certs:
        return False

    trusted_pub = trusted_certs[name].public_key().public_numbers()
    incoming_pub = incoming_cert.public_key().public_numbers()

    return trusted_pub == incoming_pub


# Sign the data with private key of the sender.
def sign_data(private_key, data: bytes) -> str:
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()



# Verify the data with the public key.
def verify_data(cert, data: bytes, signature_b64: str) -> bool:
    signature = base64.b64decode(signature_b64)
    public_key = cert.public_key()

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
    
    

# Student work }}

# Start session

def session():
    
    # Load certificate with the HELO message
    cert_text = get_certificate_text(PERSONAL_ID)

    # Load private key for signing with HELO payload
    _, my_private_key = import_certificate(PERSONAL_ID)
    
    # Create and sign the payload
    payload = f"{args.name}|{args.topic}|HELO".encode()
    signature = sign_data(my_private_key, payload)

    # Construct the message
    mesg = {'cmd': "HELO",
            'topic': args.topic, 
            'name': args.name,
            'cert': cert_text,
            'signature': signature
        }

    # publish your message through JSON to the server
    client.publish(args.topic,json.dumps(mesg))

    # show back to the user that message is send
    print(f"Sending:  '{mesg}'")

    while True:
        data = input()

        if data == 'quit':
            print("Stopping application")
            break

        # Limit the characters which can be send through text
        if len(data) > MAX_CHARS:
            print(f"You can only send text of {MAX_CHARS} characters")
            continue
     
        
# Student Work {{
        # Load the groupkey
        key = load_groupchat_key()

        # Validate key
        if key is None:
            print("You are not admitted yet.")
            continue
        
        # Encrypt message using the groupchat key.
        aad = f"{args.topic}|MESG|{args.name}".encode()
        encoded = aes_encrypt(key, aad, data)       

        # While in the chat, publish the message.
        mesg = { 'cmd': "MESG",
                 'topic': args.topic,
                 'name': args.name,
                 'encrypt_text': encoded["encrypt_text"],
                 'nonce': encoded["nonce"]
                 
                  }

# Student work }}
        # Send encrypted message also local in readable format.
        client.publish(args.topic, json.dumps(mesg))
        print(f"{args.name}: {data}")
        if gDbg: print(f"Sending: `{mesg}`")

if __name__ == '__main__':
    args = arguments()
    gDbg = args.debug
    trusted_certs = load_members(MEMBER_FOLDER)

    # print welcome message
    print(f"Welcome to NewTeamJournalists, your chosen name is: {args.name}")
    

    # connect with mqtt server 
    client = mqtt.Client(client_id=args.name, callback_api_version=mqtt.CallbackAPIVersion.VERSION2)

    # When message is received, follow the function on_message
    client.on_message=on_message

    # connect to MQTT broker
    client.connect(args.host)

    # start the MQTT loop
    client.loop_start()

    # subscribe to acchat messages / subscibe to "groupchat", invoked with start of script
    client.subscribe(args.topic)

    # start an endless loop and wait for input on the commandline
    # publish all messages as a JSON object and stop when the input is 'quit'

    session()

    # terminate the MQTT client loop
    client.loop_stop()