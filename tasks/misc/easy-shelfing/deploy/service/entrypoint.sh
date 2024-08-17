#!/bin/sh

while true; do
    socat TCP-LISTEN:31337,reuseaddr,fork EXEC:./server.py
done