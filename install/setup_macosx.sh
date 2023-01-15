#!/bin/bash

brew update
brew install redis
cd ../
python3 -m pip install -r requirements.txt
