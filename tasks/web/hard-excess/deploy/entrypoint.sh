#!/bin/bash

dd if=/dev/urandom bs=16 count=1 | xxd -ps > /tmp/excess/secret.txt

sqlite3 /tmp/excess/db.sqlite3 < /tmp/excess/migration.sql

while true; do
    socat \
        TCP-LISTEN:31338,reuseaddr,fork \
        SYSTEM:"timeout -s SIGKILL 600 node /tmp/bot/bot.js"
done &

while true; do
    cd /tmp/excess && /tmp/excess/excess
done &

sleep infinity
