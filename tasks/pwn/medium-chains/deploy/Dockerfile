FROM ubuntu:24.04

RUN apt update && apt install -y socat

WORKDIR /tmp/chains

COPY flag.txt chains entrypoint.sh ./

RUN chmod +x ./chains ./entrypoint.sh

USER nobody:nogroup

ENTRYPOINT ./entrypoint.sh
