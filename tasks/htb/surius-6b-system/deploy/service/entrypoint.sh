#!/bin/bash
export FLAG=${FLAG:-flag{example_flag}}
echo $FLAG > /root/system.txt
export FLAG=""
unset FLAG

/usr/sbin/sshd -D && bash
while true; do
done