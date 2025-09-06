#!/bin/sh

qemu-system-x86_64 \
  -M q35 \
  -m 4G \
  -cpu Haswell,-avx \
  -smp 4 \
  -machine q35,accel=tcg \
  -drive file=FreeBSD-14.3-RELEASE-amd64.qcow2,format=qcow2,if=virtio \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -device e1000,netdev=net0 \
  -nographic \
  -serial mon:stdio \
  -vga none \
  -display none
