#! /bin/sh

keyctl add user fk "load `cat $HOME/keys/fk.blob`" @u
keyctl add user fnk "load `cat $HOME/keys/fnk.blob`" @u
