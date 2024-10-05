#!/bin/bash

set -ex

rm -rf villa public/villa.tar.gz
mkdir -p villa

cp -R deploy villa/deploy

tar -cvf villa.tar ./villa/* && gzip -9 villa.tar
mv villa.tar.gz public/

rm -rf villa/
