#!/bin/bash

musl-gcc exploit.c -o exploit -static

if [ $? -ne 0 ]; then
    echo "compile failed, exiting."
    exit 1
fi

if [ ! -d "root" ]; then
    mkdir root
    cd root
    cpio -idv < ../initramfs.cpio
    cd ..
fi

mv exploit root
cd root; find . -print0 | cpio -o --null --owner=root --format=newc > ../debugfs.cpio
cd ../

/usr/bin/qemu-system-x86_64 \
    -kernel ./bzImage \
    -m 256M \
    -initrd ./debugfs.cpio \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -cpu kvm64,+smep,+smap \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1 oops=panic nokaslr" \
    -smp cores=2 \
    -s
