FROM ubuntu:22.04

RUN apt update && apt install -y socat

WORKDIR /tmp/gollum

COPY flag.txt gollum entrypoint.sh ./

RUN chmod +x ./gollum ./entrypoint.sh

USER nobody:nogroup

ENTRYPOINT ./entrypoint.sh
