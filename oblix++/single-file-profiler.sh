#!/bin/bash

if [ "$1" = "oblix++" ]
then
	grep 'Assigning stash blocks' $2 | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
	grep 'Creating Dummy' $2 | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
	grep 'First Oblivious Sort' $2 | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
	grep 'Sequential Scan on' $2 | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
	grep 'Oblivious Compaction' $2 | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
	grep 'Creating Buckets to write' $2 | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
	grep 'Padding stash' $2 | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
	grep 'Out of SGX memory write' $2 | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
else
	grep 'Creating and Filling BUFU' $2 | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
	grep 'Adding Extra Dummy' $2 | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
	grep 'Oblivious Sort' $2 | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
	grep 'Creating Buckets for write' $2 | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
	grep 'Padding Stash' $2 | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
	grep 'Out of SGX memory write' $2 | cut -d ':' -f 2 | awk '{ total += $1; count++ } END { print total/count }'
fi
