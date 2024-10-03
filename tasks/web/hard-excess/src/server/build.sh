#!/bin/bash

set -ex

docker build --tag excess-server-builder .
docker run --rm -v $PWD:/tmp/build/ excess-server-builder
