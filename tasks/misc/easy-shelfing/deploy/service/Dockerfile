FROM ubuntu:latest

RUN apt-get update -yyq && apt-get upgrade -yyq
RUN apt install socat -yyq
RUN apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -M -s /bin/false ctf
RUN pip install pwntools --break-system-packages

COPY server.py flag.txt entrypoint.sh /

RUN chmod ugo+x /server.py
RUN chmod ugo+x /entrypoint.sh
RUN chmod ugo+r flag.txt

USER ctf

ENTRYPOINT /entrypoint.sh