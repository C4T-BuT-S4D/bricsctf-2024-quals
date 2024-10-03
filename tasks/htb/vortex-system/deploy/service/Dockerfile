FROM ubuntu:latest

RUN apt-get update -yyq && apt-get upgrade -yyq
RUN apt install socat zip openssh-server sudo util-linux -yyq

RUN useradd -m -s /bin/bash xetrov
RUN echo "xetrov:KekosikIsNotMemosik!@1234" | chpasswd
RUN echo "root:tequieroelizasoloati" | chpasswd

COPY backupper entrypoint.sh /opt/
COPY system.txt /root/

RUN chmod 600 /root/system.txt

RUN chmod ugo+x /opt/backupper
RUN chmod ugo+x /opt/entrypoint.sh

RUN service ssh start

ENTRYPOINT /opt/entrypoint.sh