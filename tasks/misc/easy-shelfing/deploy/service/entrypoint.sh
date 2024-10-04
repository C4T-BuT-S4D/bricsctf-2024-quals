#!/bin/bash

export FLAG=${FLAG:-"flag{example_flag}"}
echo $FLAG > flag.txt
unset FLAG

while true; do
    socat TCP-LISTEN:31337,reuseaddr,fork EXEC:./server.py
done
