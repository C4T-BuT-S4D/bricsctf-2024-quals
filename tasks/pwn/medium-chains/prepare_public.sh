#!/bin/bash

set -ex

rm -rf chains public/chains.tar.gz
mkdir -p chains

cp -R deploy chains/deploy
cp -R src chains/src

tar -cvf chains.tar ./chains/* && gzip -9 chains.tar
mv chains.tar.gz public/

rm -rf chains/
