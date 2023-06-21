#!/bin/bash

min=512
max=33554432

if [ "$1" = "oblix++" ]
then
for (( c = $min; c <= $max ;c=c*2 ))
do
        grep 'Assigning stash blocks' $c.txt | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { printf("%d\t",total/count) }'
done
        printf '\n'
for (( c = $min; c <= $max ;c=c*2 ))
do
        grep 'Creating Dummy' $c.txt | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { printf("%d\t",total/count) }'
done
        printf '\n'
for (( c = $min; c <= $max ;c=c*2 ))
do
        grep 'First Oblivious Sort' $c.txt | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { printf("%d\t",total/count) }'
done
        printf '\n'
for (( c = $min; c <= $max ;c=c*2 ))
do
        grep 'Sequential Scan on' $c.txt | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { printf("%d\t",total/count) }'
done
        printf '\n'
for (( c = $min; c <= $max ;c=c*2 ))
do
        grep 'Oblivious Compaction' $c.txt | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { printf("%d\t",total/count) }'
done
        printf '\n'
for (( c = $min; c <= $max ;c=c*2 ))
do
        grep 'Creating Buckets to write' $c.txt | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { printf("%d\t",total/count) }'
done
        printf '\n'
for (( c = $min; c <= $max ;c=c*2 ))
do
        grep 'Padding stash' $c.txt | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { printf("%d\t",total/count) }'
done
        printf '\n'
for (( c = $min; c <= $max ;c=c*2 ))
do
        grep 'Out of SGX memory write' $c.txt | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { printf("%d\t",total/count) }'
done
        printf '\n'
else
for (( c = $min; c <= $max ;c=c*2 ))
do
	grep 'Creating and Filling BUFU' $c.txt | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { printf("%d\t",total/count) }'
done
	printf '\n'
for (( c = $min; c <= $max ;c=c*2 ))
do
        grep 'Adding Extra Dummy' $c.txt | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { printf("%d\t",total/count) }'
done
	printf '\n'
for (( c = $min; c <= $max ;c=c*2 ))
do
        grep 'Oblivious Sort' $c.txt | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { printf("%d\t",total/count) }'
done
	printf '\n'
for (( c = $min; c <= $max ;c=c*2 ))
do
        grep 'Creating Buckets for write' $c.txt | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { printf("%d\t",total/count) }'
done
	printf '\n'
for (( c = $min; c <= $max ;c=c*2 ))
do
        grep 'Padding Stash' $c.txt | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { printf("%d\t",total/count) }'
done
	printf '\n'
for (( c = $min; c <= $max ;c=c*2 ))
do
        grep 'Out of SGX memory write' $c.txt | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { printf("%d\t",total/count) }'
done
	printf '\n'
fi
