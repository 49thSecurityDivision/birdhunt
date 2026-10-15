#!/bin/sh

for user in $(awk -F':' '{ print $1 }' /etc/passwd); do
    pass=$(echo "$user$1$2" | md5sum)
    echo $pass | passwd -s $user
done
