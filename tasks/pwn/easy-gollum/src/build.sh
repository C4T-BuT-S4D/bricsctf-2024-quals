#!/bin/bash

set -ex

docker build --tag gollum-builder .
docker run --rm -v $PWD:/tmp/build/ gollum-builder
