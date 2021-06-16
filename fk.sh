#! /bin/sh

keyctl add user fk "`cat $HOME/keys/fk.blob`" @u
keyctl add user fnk "`cat $HOME/keys/fnk.blob`" @u
