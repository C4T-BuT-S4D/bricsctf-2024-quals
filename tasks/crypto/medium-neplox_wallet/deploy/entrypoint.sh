#!/bin/sh

while true; do
    socat TCP-LISTEN:31337,reuseaddr,fork EXEC:"timeout -s SIGKILL 120 ./neplox_wallet.py"
done
