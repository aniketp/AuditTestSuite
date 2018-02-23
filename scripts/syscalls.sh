#!/bin/sh
# Script to collect unique system calls from a trail

list='syslist'
syscalls='syscalls'

for line in $(cat ${list}); do
    echo $line
    found=$(cat "$syscalls" | grep "$line"); echo $found

    if [ "$found" = "" ]; then
        echo "$line" >> "$syscalls"   
        echo "$line"
    fi
done
