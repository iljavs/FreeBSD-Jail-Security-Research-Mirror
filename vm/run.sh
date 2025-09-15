#!/bin/sh

qemu-system-x86_64 \
  -m 2G \
  -cpu host \
  -smp 4 \
  -machine q35,accel=kvm \
  -drive file=FreeBSD-14.3-RELEASE-amd64.qcow2,format=qcow2 \
  -device e1000,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -nographic \
  -serial mon:stdio \
  -vga none \
  -display none
