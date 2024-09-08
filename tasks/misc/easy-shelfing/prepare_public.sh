#!/bin/bash

set -ex

rm -rf shelfing public/shelfing.tar.gz
mkdir -p shelfing/service

cp deploy/docker-compose.yml shelfing/
cp deploy/service/Dockerfile shelfing/service/
cp deploy/service/entrypoint.sh shelfing/service/
cp deploy/service/server.py shelfing/service/

echo "flag{example}" > shelfing/service/flag.txt

tar -cvf shelfing.tar ./shelfing/* && gzip -9 shelfing.tar
mv shelfing.tar.gz public/

rm -rf shelfing/
