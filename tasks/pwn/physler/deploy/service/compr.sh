#!/bin/bash

cd initramfs
find . | cpio -o -H newc -R root:root | gzip -9 > ../initramfs.cpio.gz
