#!/bin/bash

import zmq

socket = zmq.Context().socket(zmq.REP)
socket.bind("ipc:///tmp/dns_server_zmq")
while True:
    messags = socket.recv_string()
    print("recv: " + messags)
    socket.send_string("ok")