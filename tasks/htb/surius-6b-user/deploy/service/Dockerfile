FROM ubuntu:latest

RUN apt-get update -yyq && apt-get upgrade -yyq
RUN apt install ruby gem zip net-tools ncat sudo util-linux -yyq

RUN useradd -m -s /bin/bash ozon1337games
RUN gem install sinatra sinatra-basic-auth rackup

COPY user.txt /home/ozon1337games/
COPY creds.txt /home/ozon1337games/
COPY entrypoint.sh /opt/entrypoint.sh

ADD app /opt/app

RUN chmod 600 /home/ozon1337games/user.txt
RUN chmod 600 /home/ozon1337games/creds.txt
RUN chown ozon1337games:ozon1337games /home/ozon1337games/user.txt
RUN chown ozon1337games:ozon1337games /home/ozon1337games/creds.txt

RUN chmod ugo+x /opt/entrypoint.sh

WORKDIR /opt/
USER ozon1337games
ENTRYPOINT /opt/entrypoint.sh
