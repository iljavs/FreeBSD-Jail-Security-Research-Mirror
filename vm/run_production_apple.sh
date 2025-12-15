#!/bin/sh

qemu-system-x86_64 \
  -m 2G \
  -cpu Haswell \
  -smp 4 \
  -machine q35,accel=tcg \
  -drive file=FreeBSD-15.0-RELEASE-amd64-production.qcow2,format=qcow2 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -device e1000,netdev=net0,mac=52:54:00:aa:00:99 \
  -serial mon:stdio \
  -nographic \
  -vga none \
  -display none
