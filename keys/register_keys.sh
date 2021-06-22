#!/bin/sh
# Key and certificate for SSL

cd /home/cctv/work/lsc_cctv/keys

keyctl add user server_crt "`cat server.crt`" @u
keyctl add user server_key "`cat server.key`" @u

# Key for image protection.
keyctl add user fk "`cat fk.blob`" @u
keyctl add user fnk "`cat fnk.blob`" @u
