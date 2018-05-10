from mixnet import Mixnet
from time import sleep
import socket
import select

port = 57806
address = "pets.ewi.utwente.nl"

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((address, port))

# send 10 batches of 10 messages with 30 seconds interval. total time +- 5 minutes
for x in range(0,100):
    message = "PETs,Hi PETs, we are group 7. "+str(x+1);
    message = Mixnet.make_message(message.encode())
    socket.send(message)

    ready = select.select([socket], [], [], 2)
    if not ready[0]:
        print("No response")
        quit()
    data = socket.recv(4096)

    print(data)
    if (x%10==0)&(x>0) :
        print ("\n")
        sleep(30) # Time in seconds.
