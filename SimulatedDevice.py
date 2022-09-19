import  time
from lambda_function import lambda_handler
import os
import json
 
RECEIVED_MESSAGES = 0

CONNECTION_STRING = "{deviceConnectionString}"
def message_handler(event, context):
    message = 'Hello {}{}!'.format(event['first_name'], event['last_name'])
    return {
        'message' : message
        }

for property in vars(message).items():
        print ("    {}".format(property))

print("Total calls received: {}".format(RECEIVED_MESSAGES))

def main():
        print ("")

client = lambda_handler().create_from_connection_string(CONNECTION_STRING)

print ("Waiting for C2D messages, press Ctrl-C to exit")
try:

        client.on_message_received = message_handler

        while True:
            time.sleep(10000)
except KeyboardInterrupt:
        print("IoT  C2D Messaging device sample stopped")
finally:
  
        print("Shutting down IoT  Client")
        client.shutdown()
       
def lambda_handler(event, context):
        json_region = os.environ['AWS_REGION']
        return {
        'statusCode':200,
        'headers':{
            'Content-Type': 'application/json'
        },
        'body': json.dumps({
            'Region': json_region
        })
                    }