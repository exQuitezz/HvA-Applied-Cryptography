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

MAX_CHARS = 250
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
    
    if mesg['cmd'] == 'MESG':
        try:
            aad = f"{mesg['topic']}|MESG|{mesg['name']}".encode()
            key = get_chat_key()

            plaintext = aes_decrypt(
                key,
                aad,
                mesg['nonce'],
                mesg['encrypt_text']
            )

            print(f"{mesg['name']}: {plaintext}")
        except Exception as e:
            
            if gDbg: print(f"Received: '{mesg}'")

    # Receive certificate from first message in the chat "HeLO"
    elif mesg['cmd'] == 'HELO':
        try:
            client_cert = x509.load_pem_x509_certificate(mesg['cert'].encode())
            print(f"{mesg['name']} presented a certificate")

            if is_member(mesg['name'], client_cert, trusted_certs):

                payload = f"{mesg['name']}|{mesg['topic']}|HELO".encode()

                if verify_data(client_cert, payload, mesg['signature']):
                    print(f"{mesg['name']} is trusted AND proved private key")
                else:
                    print(f"{mesg['name']} FAILED signature check")

            else:
                print(f"{mesg['name']} is NOT trusted")

        except Exception as e:
            print(f"ERROR with Certificate: {e}")

# Student work {{

# local key file for encrpytion and decryption
NTJCHAT_KEY = "NTJkey.bin"

# Function to create the chat key
def get_chat_key() -> bytes:
    if os.path.exists(NTJCHAT_KEY):
        with open(NTJCHAT_KEY, "rb") as f:
            return f.read()

    # if Key doesn't exists, create a new key.
    key = os.urandom(32)
    with open(NTJCHAT_KEY, "wb") as f:
        f.write(key)

    return key
# Function to encrypt message 
def aes_encrypt(key: bytes, aad: bytes, plaintext: str) -> dict:
    nonce = os.urandom(12)
    # encrypt the data
    encrypt_text = AESGCM(key).encrypt(nonce, plaintext.encode(), aad)
    return {
        'nonce': base64.b64encode(nonce).decode(),
        'encrypt_text' : base64.b64encode(encrypt_text).decode(),
    }

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

# Check new joiner is in the member group

def is_member(name: str, incoming_cert, trusted_certs: dict) -> bool:
    if name not in trusted_certs:
        return False

    trusted_pub = trusted_certs[name].public_key().public_numbers()
    incoming_pub = incoming_cert.public_key().public_numbers()

    return trusted_pub == incoming_pub


# Sign the key
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



# verify the key is correct
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

def session():
 
    cert_text = get_certificate_text("Certificates")

# The first message in the protocol ('HELO')

    _, my_private_key = import_certificate("Certificates")

    payload = f"{args.name}|{args.topic}|HELO".encode()
    signature = sign_data(my_private_key, payload)

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
#       Handle the outgoing message.
        key = get_chat_key() # key in bytes
        aad = f"{args.topic}|MESG|{args.name}".encode() # turn metadata into bytes        
        encoded = aes_encrypt(key, aad, data) # encrypted data          

        # While in the chat, publish the message.
        mesg = { 'cmd': "MESG",
                 'topic': args.topic,
                 'name': args.name,
                 'encrypt_text': encoded["encrypt_text"],
                 'nonce': encoded["nonce"]
                 
                  }

# Student work }}
     
        client.publish(args.topic, json.dumps(mesg))
        print(f"{args.name}: {data}")
        if gDbg: print(f"Sending: `{mesg}`")

if __name__ == '__main__':
    args = arguments()
    gDbg = args.debug
    trusted_certs = load_member_certificates("NewsTeamJournal Members")

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