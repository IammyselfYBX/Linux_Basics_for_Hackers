#! /usr/bin/python3

import socket

s = socket.socket()

Port=[21,22,25,3306]


for i in range(0,4):

   s=socket.socket()

   Ports=Port[i]

   print("This is Banner for the Port")

   print(Ports)

   s.connect(("192.168.1.101", Ports))

   answer = s.recv(1024)

   print (answer)

   s.close()

print (answer)
