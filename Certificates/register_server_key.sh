#!/bin/sh
keyctl add user server_crt "`cat server.crt`" @u
keyctl add user server_key "`cat server.key`" @u
