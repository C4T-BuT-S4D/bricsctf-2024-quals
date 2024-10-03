#!/bin/bash

set -ex

rm -rf vortex public/vortex.tar.gz
mkdir -p vortex/

cp deploy/service/cli vortex/

tar -cvf vortex.tar ./vortex/* && gzip -9 vortex.tar
mv vortex.tar.gz public/

rm -rf vortex/
