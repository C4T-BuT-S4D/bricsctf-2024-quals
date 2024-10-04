#!/bin/bash

set -ex

rm -rf mlgoesbrr public/mlgoesbrr.tar.gz
mkdir -p mlgoesbrr

cp -r deploy/* mlgoesbrr/

tar --exclude='./mlgoesbrr/ydfcode/target' -cvf mlgoesbrr.tar ./mlgoesbrr/* && gzip -9 mlgoesbrr.tar
mv mlgoesbrr.tar.gz public/

rm -rf mlgoesbrr/