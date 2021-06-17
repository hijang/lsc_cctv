#! /bin/sh
keyctl add user server_crt "`cat $HOME/work/LgSecureCoding2021/Certificates/server_rsa.crt`" @u
keyctl add user server_key "`cat $HOME/work/LgSecureCoding2021/Certificates/server_rsa.key`" @u
