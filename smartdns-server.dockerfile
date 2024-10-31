FROM quay.io/frrouting/frr:10.1.1
COPY dns_server.py /
RUN sed -i 's/https/http/' /etc/apk/repositories
RUN apk --no-cache --update upgrade && apk --no-cache add ca-certificates
RUN apk add python3 py3-pip
RUN pip3 install pymongo readerwriterlock --break-system-packages

VOLUME "/etc/dnsmasq.d/"
VOLUME "/opt"
VOLUME "/etc/frr"
CMD ["bash","-c","/dns_server.py --socket=udp://127.0.0.1:33441 --log=/tmp/dns_server.log --extra=/opt/ --node_id=10.11.200.100 --dns=1.1.1.1 --mongodb=aaa & /usr/lib/frr/docker-start"]

