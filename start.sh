#!/bin/bash
nohup redis-server --bind 127.0.0.1 &> /dev/null
python3 main.py