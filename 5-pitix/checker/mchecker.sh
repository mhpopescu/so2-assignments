#!/bin/sh

set -e
set -x

mkdir -p /tmp/pitix.ro
mkdir -p /tmp/pitix.mnt

tar -xzf pitix.files.tar.gz -C /tmp/pitix.ro
./mkfs.pitix 4096 /tmp/pitix.loop

insmod pitix.ko
modprobe loop
mount -t pitix /tmp/pitix.loop /tmp/pitix.mnt -o loop


