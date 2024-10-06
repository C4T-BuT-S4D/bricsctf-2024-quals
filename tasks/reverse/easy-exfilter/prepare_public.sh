#!/bin/bash

set -ex

rm -rf exfilter public/exfilter.tar.gz
mkdir -p exfilter/se

cp dev/exfilter.ko exfilter/
cp dev/exfilter_traff.pcapng exfilter/

tar -cvf exfilter.tar ./exfilter/* && gzip -9 exfilter.tar
mv exfilter.tar.gz public/

rm -rf exfilter/
