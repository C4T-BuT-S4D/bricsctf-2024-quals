FROM sagemath/sagemath:latest

RUN sudo apt-get update -yyq # && apt-get upgrade -yyq
RUN sudo apt install socat -yyq

WORKDIR /code

COPY . /code/

RUN sudo chmod +x entrypoint.sh easy.sage
ENTRYPOINT [ "./entrypoint.sh" ]
