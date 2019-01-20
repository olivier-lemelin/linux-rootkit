#!/bin/bash

HOST='192.168.0.135'
SSHCONN="lemelino@$HOST"

ssh $SSHCONN 'mkdir -p work'
scp * $SSHCONN:work

ssh $SSHCONN 'cd work; make clean; make all; gcc -o be_root be_root.c'

