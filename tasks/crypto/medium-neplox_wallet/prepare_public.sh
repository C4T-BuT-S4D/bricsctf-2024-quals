#!/bin/bash

set -ex

rm -rf neplox_wallet public/neplox_wallet.tar.gz
mkdir -p neplox_wallet

cp -r deploy neplox_wallet/deploy

tar -cvf neplox_wallet.tar ./neplox_wallet/* && gzip -9 neplox_wallet.tar
mv neplox_wallet.tar.gz public/

rm -rf neplox_wallet/
