#!/bin/bash

DATE=`date "+%Y%m%d-%H%M%S"`
HIT_FILENAME="histlist-${DATE}"
CUR_DIR=`pwd`

cd ..
flawfinder -S --savehitlist=${CUR_DIR}/${HIT_FILENAME}.hit LgFaceRecDemoTCP_Jetson_NanoV2 Common MonitoringSystem | tee ${CUR_DIR}/${HIT_FILENAME}.txt
cd ${CUR_DIR}