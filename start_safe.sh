#!/bin/bash

cd /home/pi/csafe-safe
echo "Pulling latest safe code"
git pull

echo "Starting safe.py"
nohup python3 safe.py &

