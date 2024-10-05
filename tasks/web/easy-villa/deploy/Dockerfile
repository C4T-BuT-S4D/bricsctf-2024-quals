FROM ubuntu:22.04

RUN apt update && apt install -y wget unzip git make gcc xxd

WORKDIR /tmp/villa/

RUN mkdir /nonexistent/ \
    && chown nobody:nogroup /tmp/villa/ /nonexistent/

USER nobody:nogroup

RUN wget https://github.com/vlang/v/archive/refs/tags/0.4.8.zip \
    && unzip 0.4.8.zip \
    && rm -rf 0.4.8.zip

RUN cd ./v-0.4.8/ && make

COPY --chown=nobody:nogroup src ./
COPY --chown=nobody:nogroup entrypoint.sh ./

RUN chmod +x entrypoint.sh

CMD [ "./entrypoint.sh" ]
