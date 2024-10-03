#!/bin/bash
export FLAG=${FLAG:-flag{example_flag}}
echo $FLAG > /home/xetrov/user.txt
export FLAG=""
unset FLAG

while true; do
   socat TCP-LISTEN:31337,reuseaddr,fork EXEC:/opt/cli/cli
done