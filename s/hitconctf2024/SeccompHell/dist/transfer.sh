#!/bin/bash

musl-gcc exploit.c -o exploit -static
# gcc --no-pie -static -Wall exploit.c exploit.S -o exploit
mv exploit root
cd root; find . -print0 | cpio -o --null --owner=root --format=newc > ../debugfs.cpio
cd ../

qemu-system-x86_64 \
    -cpu qemu64,+smap \
    -m 4096M \
    -kernel bzImage \
    -initrd debugfs.cpio \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on nokaslr" \
    -monitor /dev/null \
    -netdev user,id=net0,hostfwd=tcp::22222-:22222 \
    -device e1000,netdev=net0 \
    -nographic \
    -s \
    -no-reboot

