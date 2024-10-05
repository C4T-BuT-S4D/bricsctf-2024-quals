#!/bin/bash

export FLAG=${FLAG:-"flag{example_flag}"}
echo $FLAG > flag.txt
unset FLAG

random="$(dd if=/dev/urandom bs=16 count=1 | xxd -ps)"
mv "flag.txt" "flag.${random}.txt"

cp villa.html villa.html.bak

while true; do
    sleep 30
    cp villa.html.bak villa.html
done &

./v-0.4.8/v watch -k run main.v
