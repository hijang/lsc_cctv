#!/bin/bash -x

WORKING_DIR="$HOME/work/lsc_cctv/LgFaceRecDemoTCP_Jetson_NanoV2/build"

cd $WORKING_DIR
./LgFaceRecDemoTCP_Jetson_NanoV2

ret=$?
echo "END OF cctv.sh with return code ${ret}"
exit ${ret}
