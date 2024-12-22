#!/bin/bash
/usr/bin/qemu-system-x86_64 \
    -kernel ./bzImage \
    -m 256M \
    -initrd ./initramfs.cpio \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -cpu kvm64,+smep,+smap \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1 oops=panic" \
    -smp cores=2
