#!/bin/bash

set -ex

rm -rf gollum public/gollum.tar.gz
mkdir -p gollum/src gollum/deploy

cp deploy/docker-compose.yml gollum/deploy/
cp deploy/Dockerfile gollum/deploy/
cp deploy/entrypoint.sh gollum/deploy/
cp deploy/gollum gollum/deploy/

echo "flag{example}" > gollum/deploy/flag.txt

cp -R src gollum/

tar -cvf gollum.tar ./gollum/* && gzip -9 gollum.tar
mv gollum.tar.gz public/

rm -rf gollum/
