FROM python:3.12

RUN apt-get update -yyq && apt-get upgrade -yyq
RUN apt install socat -yyq

RUN useradd -M -s /bin/false ctf

COPY server.py flag.txt entrypoint.sh /

RUN chmod ugo+x /server.py
RUN chmod ugo+x /entrypoint.sh
RUN chmod ugo+rw flag.txt

USER ctf

ENTRYPOINT /entrypoint.sh
