#!/bin/sh
cd /opt/app
while true; do
	ruby panel.rb -o 0.0.0.0
done
