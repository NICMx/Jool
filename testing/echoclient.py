#!/bin/env python
# Echo client program
import socket
import sys

HOST = 'fec0:24::c0a8:0180'    # The remote host
PORT = 5000              # The same port as used by the server
s = None
for res in socket.getaddrinfo(HOST, PORT, socket.AF_INET6, socket.SOCK_DGRAM):
    af, socktype, proto, canonname, sa = res
    try:
        s = socket.socket(af, socktype, proto)
    except socket.error, msg:
        s = None
        continue
    try:
        s.connect(sa)
    except socket.error, msg:
        s.close()
        s = None
        continue
    break
if s is None:
    print 'could not open socket'
    sys.exit(1)
s.sendall('Hello, world')
data = s.recv(1024)
s.close()
print 'Received', repr(data)
