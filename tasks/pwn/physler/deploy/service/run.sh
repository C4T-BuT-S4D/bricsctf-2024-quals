#!/bin/sh

qemu-system-x86_64 \
    -s -m 96M \
    -cpu kvm64,+smep,+smap \
    -kernel /task/kernel/bzImage \
    -initrd initramfs.cpio.gz \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1"
