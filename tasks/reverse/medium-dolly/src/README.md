# How to build

1. Build docker image with all requirements

```sh
docker build --tag dolly-builder .
```

2. Start a container and run `build.sh`

```sh
docker run --rm -it -v $PWD:/tmp/build dolly-builder sh -c "cd /tmp/build && ./build.sh"
```

_Note: you need to craft the final patches manually ([patch.py](dolly/patch.py))_

3. Create a dist archive

```sh
tar -cvf dolly.tar dolly/dolly dolly/README.txt && gzip -9 dolly.tar
```

4. Clean

```sh
./clean-all.sh
```
