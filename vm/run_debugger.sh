#!/bin/sh

qemu-system-x86_64 \
  -m 2G \
  -cpu host \
  -smp 2 \
  -machine q35,accel=kvm \
  -drive file=FreeBSD-14.3-RELEASE-amd64-debugger.qcow2,format=qcow2 \
  -netdev user,id=net0 \
  -device e1000,netdev=net0,mac=52:54:00:aa:00:03 \
  -netdev socket,id=net1,connect=:12346 \
  -device e1000,netdev=net1,mac=52:54:00:aa:00:04 \
  -nographic \
  -serial mon:stdio \
  -vga none \
  -display none
