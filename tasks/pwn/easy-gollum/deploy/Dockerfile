FROM ubuntu:22.04

RUN apt update && apt install -y socat

WORKDIR /tmp/gollum

RUN chown nobody:nogroup ./

COPY gollum entrypoint.sh ./

RUN chmod +x ./gollum ./entrypoint.sh

USER nobody:nogroup

ENTRYPOINT ./entrypoint.sh
