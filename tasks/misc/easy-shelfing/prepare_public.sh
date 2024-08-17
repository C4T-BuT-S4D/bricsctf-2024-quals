#!/bin/bash

set -ex

rm -rf shelfing public/shelfing.tar.gz
mkdir -p shelfing/deploy

cp deploy/docker-compose.yml shelfing/deploy/
cp deploy/service/Dockerfile shelfing/deploy/
cp deploy/service/entrypoint.sh shelfing/deploy/
cp deploy/service/server.py shelfing/deploy/

echo "flag{example}" > shelfing/deploy/flag.txt

tar -cvf shelfing.tar ./shelfing/* && gzip -9 shelfing.tar
mv shelfing.tar.gz public/

rm -rf shelfing/