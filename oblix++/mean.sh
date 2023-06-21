#!/bin/bash
echo "" > mean.txt
for i in {1..10}
do
   ./app >> mean.txt
done
grep "time" mean.txt | awk '{ total += $2; count++ } END { print total/count }'
#grep "Obliv" mean.txt | awk '{ total += $3; count++ } END { print total/count }'
#grep "Time" mean.txt | awk '{ total += $4; count++ } END { print total/count }'
