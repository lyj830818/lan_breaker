#!/usr/bin/env python
#-*- coding: utf-8 -*-

import socket
from time import sleep

if __name__ == '__main__':
    HOST = '127.0.0.1'
    PORT = 3333
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(10)
    while 1:

        conn, addr = s.accept()
        print'Connected by', addr
        while 1:

            data = conn.recv(1024)

            if data:
                print data
                #sleep(20)
                conn.send("got")
            else:
                break

        conn.close()
