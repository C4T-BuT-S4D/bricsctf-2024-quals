#!/bin/bash

set -ex

rm -rf excess public/excess.tar.gz
mkdir -p excess

cp -r deploy excess/deploy
cp -r src excess/src

tar -cvf excess.tar ./excess/* && gzip -9 excess.tar
mv excess.tar.gz public/

rm -rf excess/
