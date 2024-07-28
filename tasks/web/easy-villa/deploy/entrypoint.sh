#!/bin/bash

random="$(dd if=/dev/urandom bs=16 count=1 | xxd -ps)"
mv "flag.txt" "flag.${random}.txt"

cp villa.html villa.html.bak

( while true; do sleep 20 && cp villa.html.bak villa.html; done ) &

./v-0.4.7/v watch run main.v
