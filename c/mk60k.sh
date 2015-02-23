#!/bin/bash

string="012345678901234567890123456789012345678901234567890123456789"
i=0

while (( i<500 )) 
do
  echo $string
  (( i += 1 ))
done
