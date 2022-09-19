import random
import sys
from lambda_function import lambda_handler

MESSAGE_COUNT = 2
AVG_WIND_SPEED = 10.0
MSG_TXT = "{\"service client sent a message\": %.2f}"

CONNECTION_STRING = "{IoTHubConnectionString}"
DEVICE_ID = "{deviceId}"

def iothub_messaging_sample_run():
    try:
      
        registry_manager = lambda_handler or(CONNECTION_STRING)

        for i in range(0, MESSAGE_COUNT):
            print ( 'Sending message: {0}'.format(i) )
            data = MSG_TXT % (AVG_WIND_SPEED + (random.random() * 4 + 2))

            props={}
       
            props.update(messageId = "message_%d" % i)
            props.update(correlationId = "correlation_%d" % i)
            props.update(contentType = "application/json")

        
            prop_text = "PropMsg_%d" % i
            props.update(testProperty = prop_text)

            registry_manager.send_c2d_message(DEVICE_ID, data, properties=props)

        try:
      
            raw_input("Press Enter to continue...\n")
        except:
            pass

            input("Press Enter to continue...\n")

    except Exception as ex:
        print ( "Unexpected error {0}" % ex )
        return
    except KeyboardInterrupt:
        print ( "IoT C2D Messaging service sample stopped" )
        if __name__ == '__main__':
            print ( "Starting the Python IoT Hub C2D Messaging service sample..." )

    iothub_messaging_sample_run()