#!/bin/bash

set -ex

rm -rf gollum public/gollum.tar.gz
mkdir -p gollum

cp -R deploy gollum/deploy
cp -R src gollum/src

tar -cvf gollum.tar ./gollum/* && gzip -9 gollum.tar
mv gollum.tar.gz public/

rm -rf gollum/
