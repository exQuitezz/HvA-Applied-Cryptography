
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

MAX_CHARS = 250

def arguments():
    # parse arguments
    parser = argparse.ArgumentParser(description='Basic chat application')
    
    # host MQTT server 
    parser.add_argument('--host', help='Hostname of the MQTT service, i.e. test.mosquitto.org', required=False, default="test.mosquitto.org")
    
    # Chat groupname
    parser.add_argument('--topic', help="MQTT chat topic (default '/acchat')", default='/NewTeamJournalists', required=False)
    
    # Name to join the chat
    parser.add_argument('--name', help="MQTT client name (default, a random string)", required=False)
    
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

# Student work {{

# local key file for encrpytion and decryption
NTJCHAT_KEY = "NTJkey.bin"


# check if an key exists else create a key
def get_chat_key() -> bytes:
    if os.path.exists(NTJCHAT_KEY):
        return open(NTJCHAT_KEY, "rb").read()
    # generate AES key
    key = os.urandom(32)  
    open(NTJCHAT_KEY, "wb").write(key)
    return key

# Encrypt message 

def aes_encrypt(key: bytes, aad: bytes, plaintext: str) -> dict:
    nonce = os.urandom(12)
    # encrypt the data
    encrypt_text = AESGCM(key).encrypt(nonce, plaintext.encode(), aad)
    return {
        'nonce': base64.b64encode(nonce).decode(),
        'encrypt_text' : base64.b64encode(encrypt_text).decode(),
    }

# Decrypt received message
def aes_decrypt(key: bytes, aad: bytes, nonce_b64: str, enc_b64: str) -> str:
    nonce = base64.b64decode(nonce_b64)
    encrypt_bytes = base64.b64decode(enc_b64)  
    decrypt_bytes = AESGCM(key).decrypt(nonce, encrypt_bytes, aad) 
    return decrypt_bytes.decode()  


# Student work }}

def session():
    
 
# The first message in the protocol ('HELO')
    mesg = {'cmd': "HELO",
            'topic': args.topic, 
            'name': args.name,
        
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
        if gDbg: print(f"Sending: `{mesg}`")

if __name__ == '__main__':
    args = arguments()
    gDbg = args.debug

    # generate a random client name if nothing is provided
    if args.name is None:
        alphabet = string.ascii_letters + string.digits
        args.name = ''.join(secrets.choice(alphabet) for i in range(8))

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