#!/bin/sh
/usr/sbin/sshd -D & 

while true; do
    runuser -l xetrov -c "socat TCP-LISTEN:31337,reuseaddr,fork EXEC:/opt/cli/cli"
done