#!/bin/bash

cd /home/pi/csafe-safe
echo "Pulling latest safe code"
/bin/su -c "cd /home/pi/csafe-safe; git pull" - pi

echo "Starting safe.py"
nohup python3 safe.py &

