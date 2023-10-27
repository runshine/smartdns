#!/bin/bash

docker buildx build . -f smartdns.dockerfile        -t runshine0819/smartdns:latest        --platform linux/amd64,linux/arm64,linux/arm --push
docker buildx build . -f smartdns-server.dockerfile -t runshine0819/smartdns-server:latest --platform linux/amd64,linux/arm64,linux/arm --push
