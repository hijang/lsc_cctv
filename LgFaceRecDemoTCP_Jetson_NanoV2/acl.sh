#!/bin/bash

mkdir logs
chown cctv:manager ./logs -R
chmod 740 ./logs -R

chown cctv:cctv ./imgs -R
chmod 700 ./imgs -R

chown cctv:manager ./build/UserRegister
chmod 4710 ./build/UserRegister
