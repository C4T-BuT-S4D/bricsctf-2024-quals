#!/bin/bash

set -ex

rm -rf mlgoesbrr public/excess.tar.gz
mkdir -p mlgoesbrr

cp -r deploy/* mlgoesbrr/

echo "brics+{123}" > mlgoesbrr/flag.txt

tar --exclude='./mlgoesbrr/ydfcode/target' -cvf mlgoesbrr.tar ./mlgoesbrr/* && gzip -9 mlgoesbrr.tar
mv mlgoesbrr.tar.gz public/

rm -rf mlgoesbrr/