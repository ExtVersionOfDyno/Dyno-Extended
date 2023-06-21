#!/bin/bash

min=512
max=33554432
for (( c = $min; c <= $max ;c=c*2 ))
do
grep 'Total Access Time:' $c.txt  | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
done
