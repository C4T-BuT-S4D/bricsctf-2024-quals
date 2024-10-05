#!/bin/bash

set -ex

rm -rf bigblackcode public/bigblackcode.tar.gz
mkdir -p bigblackcode

cp -r deploy bigblackcode/deploy

tar -cvf bigblackcode.tar ./bigblackcode/* && gzip -9 bigblackcode.tar
mv bigblackcode.tar.gz public/

rm -rf bigblackcode/
