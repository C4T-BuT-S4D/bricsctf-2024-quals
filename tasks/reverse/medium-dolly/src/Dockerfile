FROM ubuntu:18.04

RUN apt update
RUN apt install -y binutils curl wget make zip unzip python3 libpthread-stubs0-dev patch gcc g++-9 openjdk-11-jdk-headless

RUN sh -c "cp $(which clang++-9) /usr/bin/g++"

CMD [ "/bin/bash" ]
