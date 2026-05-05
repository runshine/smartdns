FROM ubuntu:latest

RUN apt update && \
    apt install -y make gcc libssl-dev ca-certificates && \
    mkdir -p /build/smartdns/

COPY . /build/smartdns/
RUN cd /build/smartdns && \
    STATIC=no sh ./package/build-pkg.sh --platform linux --arch `dpkg --print-architecture` && \
    ( cd package && tar -xvf *.tar.gz && chmod a+x smartdns/etc/init.d/smartdns ) && \
    mkdir -p /release/var/log && \
    cp package/smartdns/etc /release/ -a && \
    cp package/smartdns/usr /release/ -a && \
    cp -a /release/. / && \
    cd / && rm -rf /build /release

VOLUME "/etc/smartdns/"
CMD ["/usr/sbin/smartdns","-f","-x","-u","udp://127.0.0.1:1234"]
