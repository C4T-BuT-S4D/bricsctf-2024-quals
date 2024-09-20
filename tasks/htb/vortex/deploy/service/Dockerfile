FROM ubuntu:latest

RUN apt-get update -yyq && apt-get upgrade -yyq
RUN apt install socat zip openssh-server sudo util-linux -yyq

RUN useradd -m -s /bin/bash xetrov
RUN echo "xetrov:KekosikIsNotMemosik!@1234" | chpasswd
RUN echo "root:tequieroelizasoloati" | chpasswd

COPY backuper entrypoint.sh /opt/
COPY user.txt /home/xetrov/
COPY system.txt /root/
COPY db.conf /home/xetrov/

RUN mkdir /opt/cli
COPY cli /opt/cli

RUN chmod ugo+rw /opt/cli
RUN chown xetrov:xetrov /opt/cli

RUN chmod 700 /home/xetrov/user.txt
RUN chown xetrov:xetrov /home/xetrov/user.txt

RUN chmod 700 /home/xetrov/db.conf
RUN chown xetrov:xetrov /home/xetrov/db.conf

RUN chmod 700 /root/system.txt

RUN chmod ugo+x /opt/backuper
RUN chmod ugo+x /opt/cli/cli
RUN chmod ugo+x /opt/entrypoint.sh
RUN /opt/backuper

RUN service ssh start

WORKDIR /opt/cli/
ENTRYPOINT /opt/entrypoint.sh