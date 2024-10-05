#!/bin/sh

while true; do
    socat TCP-LISTEN:31337,reuseaddr,fork EXEC:"timeout -s SIGKILL 60 ./easy.sage"
done
