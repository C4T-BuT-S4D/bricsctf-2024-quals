#!/bin/bash

set -ex

rm -rf xoshiro256++ public/xoshiro256++.tar.gz
mkdir -p xoshiro256++

cp src/a.jl xoshiro256++/
cp src/output.txt xoshiro256++/


tar -cvf xoshiro256++.tar ./xoshiro256++/* && gzip -9 xoshiro256++.tar
mv xoshiro256++.tar.gz public/

rm -rf xoshiro256++/
