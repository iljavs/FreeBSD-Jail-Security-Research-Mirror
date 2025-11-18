#!/bin/sh

qemu-system-x86_64 \
  -m 16G \
  -cpu host \
  -smp 10 \
  -machine q35,accel=kvm \
  -drive file=FreeBSD-14.3-RELEASE-amd64-target.qcow2,format=qcow2 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -device e1000,netdev=net0,mac=52:54:00:aa:00:01 \
  -netdev socket,id=net1,listen=:12346 \
  -device e1000,netdev=net1,mac=52:54:00:aa:00:02 \
  -serial mon:stdio \
  -serial tcp:0.0.0.0:4444,server,nowait \
  -nographic \
  -vga none \
  -display none
