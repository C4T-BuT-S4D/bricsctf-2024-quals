#!/bin/bash

set -ex

docker build --tag chains-builder .
docker run --rm -v $PWD:/tmp/build/ chains-builder
