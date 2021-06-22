#!/bin/bash -x

WORKING_DIR="$HOME/work/lsc_cctv/LgFaceRecDemoTCP_Jetson_NanoV2/build"
# register key on initial stage
cd $HOME/work/lsc_cctv/keys
./register_keys.sh

# launch server
cd $WORKING_DIR
./LgFaceRecDemoTCP_Jetson_NanoV2

ret=$?
echo "END OF cctv.sh with return code ${ret}"
exit ${ret}
