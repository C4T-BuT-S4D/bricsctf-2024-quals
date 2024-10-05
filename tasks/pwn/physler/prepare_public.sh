#!/bin/bash

set -ex

rm -rf physler public/physler.tar.gz
mkdir -p physler/service

cp deploy/docker-compose.yml physler/
cp deploy/service/Dockerfile physler/service/
cp deploy/service/compr.sh physler/service/
cp deploy/service/decompress.sh physler/service/
cp deploy/service/initramfs.cpio.gz physler/service/
cp deploy/service/run.sh physler/service/
cp deploy/service/bzImage physler/service/
cp dev/physler.c physler/
cp dev/physler.h physler/
cp dev/Makefile physler/

tar -cvf physler.tar ./physler/* && gzip -9 physler.tar
mv physler.tar.gz public/

rm -rf physler/
