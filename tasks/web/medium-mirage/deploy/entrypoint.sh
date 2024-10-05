#!/bin/bash

while true; do
    socat \
        TCP-LISTEN:31338,reuseaddr,fork \
        SYSTEM:"timeout -s SIGKILL 600 node /tmp/bot/bot.js"
done &

while true; do
    cd /tmp/mirage && dotnet run
done &

sleep infinity
