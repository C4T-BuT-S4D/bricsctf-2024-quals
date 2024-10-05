FROM python:3.10

RUN apt-get update -yyq # && apt-get upgrade -yyq
RUN apt install socat -yyq

WORKDIR /code

COPY . /code/

RUN chmod +x entrypoint.sh neplox_wallet.py
ENTRYPOINT [ "./entrypoint.sh" ]
