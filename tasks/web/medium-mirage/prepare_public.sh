#!/bin/bash

set -ex

rm -rf mirage public/mirage.tar.gz
mkdir -p mirage

cp -r deploy mirage/deploy

tar -cvf mirage.tar ./mirage/* && gzip -9 mirage.tar
mv mirage.tar.gz public/

rm -rf mirage/
