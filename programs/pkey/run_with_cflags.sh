#!/bin/bash

function build {
  OPT=$1
  echo "***** CLAGS=-O${OPT} *******"
  cd ../../library
  make clean
  make CFLAGS=-O${OPT}
  cd ../programs/pkey
  make clean
  make run
  ls -l rsa_verify_no_fs;
}

build 3
build 2
build s
