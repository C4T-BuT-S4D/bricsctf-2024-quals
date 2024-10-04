#!/bin/sh
cd /opt/app

export FLAG=${FLAG:-"flag{example_flag}"}
echo $FLAG > /home/ozon1337games/user.txt
export FLAG=""
unset FLAG

while true; do
	ruby panel.rb -o 0.0.0.0
done
