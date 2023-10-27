#!/bin/bash

docker build . -f smartdns.dockerfile -t runshine0819/smartdns:$(uname -m)
docker build . -f smartdns-server.dockerfile -t runshine0819/smartdns-server:latest --network host
