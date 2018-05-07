from cryptography.fernet import Fernet
import socket
import sys
import select
import struct

port = 55010
address = "pets.ewi.utwente.nl"

plaintext = "Bob,test message to Bob"

plaintextbytes = plaintext.encode()
outmsg = bytearray(struct.pack('>I', len(plaintextbytes)))
outmsg.extend(plaintextbytes)
print(outmsg)

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((address, port))
socket.send(outmsg)

ready = select.select([socket], [], [], 2)
if not ready[0]:
	print("No response")
	quit()
data = socket.recv(4096)

print(data)