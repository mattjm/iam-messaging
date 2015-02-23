#!/bin/bash

# generate a cert/key pair for signing

name=$1
[[ -z $name ]] && {
   echo "usage: $0 output_file_prefix"
   exit 1
}

openssl req -newkey 2048 -x509 -nodes -out ${name}.crt -keyout ${name}.key 
