from mixnet import Mixnet
import socket
import select

port = 52072
address = "pets.ewi.utwente.nl"
    
message = Mixnet.make_message("Bob,test message to Bob".encode())

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((address, port))
socket.send(message)

ready = select.select([socket], [], [], 2)
if not ready[0]:
    print("No response")
    quit()
data = socket.recv(4096)

print(data)