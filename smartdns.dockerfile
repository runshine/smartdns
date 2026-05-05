FROM ubuntu:latest as smartdns-builder
LABEL previous-stage=smartdns-builder

# prepare builder
ARG OPENSSL_VER=1.1.1f
RUN apt update && \
    apt install -y make gcc libssl-dev && \
    mkdir -p /build/smartdns/

# do make
COPY . /build/smartdns/
RUN cd /build/smartdns && \
    STATIC=no sh ./package/build-pkg.sh --platform linux --arch `dpkg --print-architecture` && \
    \
    ( cd package && tar -xvf *.tar.gz && chmod a+x smartdns/etc/init.d/smartdns ) && \
    \
    mkdir -p /release/var/log /release/var/run && \
    cp package/smartdns/etc /release/ -a && \
    cp package/smartdns/usr /release/ -a && \
    cd / && rm -rf /build

FROM ubuntu:latest
RUN apt update && \
    apt install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=smartdns-builder /release/ /
VOLUME "/etc/smartdns/"
CMD ["/usr/sbin/smartdns","-f","-x","-u","udp://127.0.0.1:1234"]
