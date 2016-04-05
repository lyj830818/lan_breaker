#!/usr/bin/env python
#-*- coding: utf-8 -*-

import socket
if __name__ == '__main__':
    HOST = '127.0.0.1'
    PORT = 3356
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    # s.settimeout(5.0)
    s.connect((HOST, PORT))

    while 1:
        str = raw_input("Please input:")
        print str
        if str:
            s.sendall(str)
            data = s.recv(8192)
            print data

        else:
            break

    s.close()