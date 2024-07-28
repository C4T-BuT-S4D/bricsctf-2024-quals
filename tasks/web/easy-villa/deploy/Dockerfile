FROM ubuntu:22.04

RUN apt update && apt install -y wget unzip git make gcc xxd

WORKDIR /tmp/villa/

RUN chmod 777 /tmp/villa/ \
    && mkdir /nonexistent/ \
    && chown nobody:nogroup /nonexistent/

USER nobody:nogroup

RUN wget https://github.com/vlang/v/archive/refs/tags/0.4.7.zip \
    && unzip 0.4.7.zip \
    && rm -rf 0.4.7.zip

RUN cd ./v-0.4.7/ && make

COPY --chown=nobody:nogroup entrypoint.sh main.v flag.txt *.html ./

RUN chmod +x entrypoint.sh

ENTRYPOINT [ "./entrypoint.sh" ]
