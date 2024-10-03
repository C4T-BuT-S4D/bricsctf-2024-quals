FROM ubuntu:latest

RUN apt-get update -yyq && apt-get upgrade -yyq
RUN apt install socat zip util-linux -yyq

RUN useradd -m -s /bin/bash xetrov

COPY entrypoint.sh /opt/
COPY user.txt /home/xetrov/
COPY db.conf /home/xetrov/

RUN mkdir /opt/cli
COPY cli /opt/cli

RUN chmod ugo+rw /opt/cli
RUN chown xetrov:xetrov /opt/cli

RUN chmod 600 /home/xetrov/user.txt
RUN chown xetrov:xetrov /home/xetrov/user.txt

RUN chmod 600 /home/xetrov/db.conf
RUN chown xetrov:xetrov /home/xetrov/db.conf

RUN chmod ugo+x /opt/cli/cli
RUN chmod ugo+x /opt/entrypoint.sh

WORKDIR /opt/cli/
USER xetrov
ENTRYPOINT /opt/entrypoint.sh