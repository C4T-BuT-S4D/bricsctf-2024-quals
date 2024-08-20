#!/bin/bash

set -ex

rm -rf chains public/chains.tar.gz
mkdir -p chains/src chains/deploy

cp deploy/chains chains/deploy/
cp deploy/docker-compose.yml chains/deploy/
cp deploy/Dockerfile chains/deploy/
cp deploy/entrypoint.sh chains/deploy/

echo "flag{example}" > chains/deploy/flag.txt

cp -R src chains/

tar -cvf chains.tar ./chains/* && gzip -9 chains.tar
mv chains.tar.gz public/

rm -rf chains/
