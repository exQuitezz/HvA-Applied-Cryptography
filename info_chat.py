# pip3 install paho-mqtt
# (c) HvA Pieter Meulenhof, Frans Schippers
#

import paho.mqtt.client as mqtt
import argparse
import time
import string
import secrets
import json

from cryptography import x509


def arguments():
    # parse arguments
    parser = argparse.ArgumentParser(description='Basic chat application')
    parser.add_argument('--host', help='Hostname of the MQTT service, i.e. test.mosquitto.org', required=False, default="test.mosquitto.org")
    parser.add_argument('--topic', help="MQTT chat topic (default '/acchat')", default='/acchat', required=False)
    parser.add_argument('--name', help="MQTT client name (default, a random string)", required=False)
    parser.add_argument('--debug', '-D', help="Debug mode", action='store_true', required=False)
    return parser.parse_args()

# on message handler
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
        # ignore messages that do not have a client id
        return

    if mesg['name'] == args.name:
        # ignore messages sent by me
        return

    if not 'cmd' in mesg:
        # ignore messages without a command
        return

    if gDbg: print(f"Received: '{mesg}'")

# Student work {{
#   Handle the different message-type
# Student work }}

def session():
    # The first message in the protocol ('HELO')
    mesg = { 'cmd': "HELO", 'name': args.name }
    client.publish(args.topic,json.dumps(mesg))
    print(f"Sending:  '{mesg}'")
    while True:
        data = input()
        if data == 'quit':
            print("Stopping application")
            break

# Student Work {{
#       Handle the outgoing message.

        # publish a unencrypted message to the chat (shouls be removed
        mesg = { 'cmd': "MESG", 'name': args.name, 'mesg': data }
# Student work }}

        client.publish(args.topic, json.dumps(mesg))
        if gDbg: print(f"Sending: `{mesg}`")

if __name__ == '__main__':
    args = arguments()
    gDbg = args.debug

    # generate a random client id if nothing is provided
    if args.name is None:
        alphabet = string.ascii_letters + string.digits
        args.name = ''.join(secrets.choice(alphabet) for i in range(8))

    # print welcome message
    print(f"Basic chat started, my client id is: {args.name}")
    
    # create MQTT client
    client = mqtt.Client(client_id=args.name, callback_api_version=mqtt.CallbackAPIVersion.VERSION2)

    # connect the message handler when something is received
    client.on_message=on_message

    # connect to MQTT broker
    client.connect(args.host)

    # start the MQTT loop
    client.loop_start()

    # subscribe to acchat messages
    client.subscribe(args.topic)

    # start an endless loop and wait for input on the commandline
    # publish all messages as a JSON object and stop when the input is 'quit'

    session()

    # terminate the MQTT client loop
    client.loop_stop()
