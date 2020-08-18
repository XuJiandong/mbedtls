#!/bin/bash

FN=comparison.txt
function build {
  OPT=$1
  echo "***** CLAGS=-O${OPT} *******"
  cd ../../library
  make clean
  make CFLAGS=-O${OPT}
  cd ../programs/pkey
  make clean
  make CFLAGS=-O${OPT}
  make run | tee -a $FN
  ls -l rsa_verify_no_fs | tee -a $FN
}

mv $FN "$FN.old"
build 3
build 2
build s
