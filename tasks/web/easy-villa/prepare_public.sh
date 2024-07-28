#!/bin/bash

set -ex

rm -rf villa public/villa.tar.gz
mkdir -p villa

cp deploy/docker-compose.yml villa/
cp deploy/Dockerfile villa/
cp deploy/entrypoint.sh villa/
cp deploy/index.html villa/
cp deploy/main.v villa/
cp deploy/template.html villa/
cp deploy/villa.html villa/

echo "flag{example}" > villa/flag.txt

tar -cvf villa.tar ./villa/* && gzip -9 villa.tar
mv villa.tar.gz public/

rm -rf villa/
