#!/bin/bash

set -ex

docker build --tag excess-client-builder .
docker run --rm -v $PWD:/tmp/build/ excess-client-builder
