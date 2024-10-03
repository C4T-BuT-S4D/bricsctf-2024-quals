FROM ubuntu:latest

RUN apt-get update -yyq && apt-get upgrade -yyq
RUN apt install zip net-tools openssh-server ncat sudo util-linux -yyq

RUN useradd -m -s /bin/bash ozon1337games

RUN echo "ozon1337games:Ooo000_ti_dumal_tut_chto-to_budet??" | chpasswd

COPY system.txt /root/
COPY entrypoint.sh /opt/entrypoint.sh

COPY escape /opt/

RUN chmod u+s /opt/escape
RUN chmod 600 /root/system.txt
RUN chmod ugo+x /opt/entrypoint.sh

RUN service ssh start

WORKDIR /opt/
ENTRYPOINT /opt/entrypoint.sh
