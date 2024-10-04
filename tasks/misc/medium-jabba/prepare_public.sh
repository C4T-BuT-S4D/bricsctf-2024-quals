#!/bin/bash

set -ex

rm -rf jabba public/jabba.tar.gz
mkdir -p jabba

cp -r deploy jabba/deploy

tar -cvf jabba.tar ./jabba/* && gzip -9 jabba.tar
mv jabba.tar.gz public/

rm -rf jabba/
