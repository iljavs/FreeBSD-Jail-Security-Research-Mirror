# VM setup guide

## Synopsis

This guide explains how to set up a FreeBSD virtual machine using [QEMU](https://www.qemu.org/), compile a GENERIC-DEBUG kernel and set up an online debugging environment. The virtual disk image is then cloned to spin up a second FreeBSD virtual machine that can is reconfigured to run the online debugger.

## Prebuilt images

Two prebuilt qcow2 images, compatible with the `run___.sh` scripts, are available for download from https://hacktheplanet.be/philez/freebsd/, which means you can skip this entire guide. Both images run a GENERIC-DEBUG kernel and have kgdb installed. The target image has been configured to run a jail to help with proof of concept exploit development and has a serial debug port enabled. The debugger image has everything you need to remotely debug the target. Download, decompress and use them with the appropriate `run___.sh ` script. The root password is `foobar`.

## Fetch the FreeBSD 14.3-RELEASE installation ISO

```sh
curl -sL https://download.freebsd.org/releases/amd64/amd64/ISO-IMAGES/14.3/FreeBSD-14.3-RELEASE-amd64-bootonly.iso.xz \
  | xz -d > /tmp/FreeBSD-14.3-RELEASE-amd64-bootonly.iso
```

## Create a virtual disk

```sh
qemu-img create -f qcow2 FreeBSD-14.3-RELEASE-amd64.qcow2 20G
```

## Boot the VM for FreeBSD installation

```sh
qemu-system-x86_64 \
  -m 4G \
  -cpu host \
  -smp 4 \
  -machine q35,accel=kvm \
  -drive file=FreeBSD-14.3-RELEASE-amd64.qcow2,format=qcow2 \
  -cdrom /tmp/FreeBSD-14.3-RELEASE-amd64-bootonly.iso \
  -boot d \
  -device e1000,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22
```

## Install FreeBSD with mostly defaults

- Distribution Select: base-dbg, kernel-dbg, lib32-dbg, lib32, src
- Partitioning: Guided UFS Disk Setup, Entire disk, MBR
- Time Zone: Europe/Belgium
- System configuration: sshd
- System Hardening: keep defaults (no extra hardening options enabled)
- Extra users: no need

Shut down the VM

## Boot the VM for configuration

```sh
qemu-system-x86_64 \
  -m 4G \
  -cpu host \
  -smp 4 \
  -machine q35,accel=kvm \
  -drive file=FreeBSD-14.3-RELEASE-amd64.qcow2,format=qcow2 \
  -device e1000,netdev=net0,mac=52:54:00:aa:00:01 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22
```

## Enable ssh root login for convenience

```sh
sed -i '' 's/^#PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i '' 's/^#PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
service sshd restart
```

## SSH into the VM to continue configuration

Connecting to the VM through ssh makes it easier to copy paste the configuration commands that follow. Doing this over a serial console has issues because of lag / buffer / missing characters and will cause you a world of pain. Ask me how I know, please do.

```sh
ssh -p 2222 -o PreferredAuthentications=password -o PubkeyAuthentication=no root@localhost
```

## Update `loader.conf`

```sh
cat << 'EOF' > /boot/loader.conf
autoboot_delay=3
console="comconsole"
boot_serial="YES"

# Extra serial configuration for console and debugger to co-exist
boot_multicons="YES"
gdb_port="0x2f8"
gdb_debugger="YES"
gdb_enable="YES"
EOF
```

## Update `device.hints`

This is necessary to make sure uart1 is available as a serial debug port.

```sh
cat << 'EOF' >> /boot/device.hints
hint.uart.1.flags="0x90"
EOF
```

## Update `sysctl.conf`

Give the hacker time to take a screenshot of the spoils.

```sh
cat << 'EOF' > /etc/sysctl.conf
kern.panic_reboot_wait_time=5
debug.debugger_on_panic=1
debug.kdb.current=gdb
EOF
```

## Update `rc.conf`

```sh
cat << 'EOF' > /etc/rc.conf
hostname="prisonbreak-target"
ifconfig_em0="up"
sshd_enable="YES"
moused_nondefault_enable="NO"
dumpdev="NO"
jail_enable="YES"
jail_parallel_start="YES"

# Network to host for internet access
defaultrouter="10.0.2.2"
cloned_interfaces="bridge0"
ifconfig_bridge0="inet 10.0.2.15/24 addm em0 up"

# Network between target and debugger VM to copy kernel image and other files
ifconfig_em1="inet 192.168.100.1/24"
EOF
```

## Set up a jail directory tree

```sh
mkdir /usr/local/jails/
mkdir /usr/local/jails/media
mkdir /usr/local/jails/containers
```

## Fetch userland for jail

```sh
fetch https://download.freebsd.org/ftp/releases/amd64/amd64/14.3-RELEASE/base.txz -o /usr/local/jails/media/14.3-RELEASE-base.txz
```

## Create a proof of concept jail

```sh
mkdir -p /usr/local/jails/containers/prisonbreak
tar -xf /usr/local/jails/media/14.3-RELEASE-base.txz -C /usr/local/jails/containers/prisonbreak --unlink
```

## Copy over timezone and DNS configuration files

```sh
cp /etc/resolv.conf /usr/local/jails/containers/prisonbreak/etc/resolv.conf
cp /etc/localtime /usr/local/jails/containers/prisonbreak/etc/localtime
```

## Configure jails

```sh
cat << 'EOF' > /etc/jail.conf
.include "/etc/jail.conf.d/*.conf";
EOF
```

## Configure a proof of concept jail

```sh
cat << 'EOF' > /etc/jail.conf.d/prisonbreak.conf
prisonbreak {
  # NETWORKING VARIABLES
  $id = "100";
  $ip = "10.0.2.${id}/24";
  $gateway = "10.0.2.2";
  $bridge = "bridge0";
  $epair = "epair${id}";

  # STARTUP/LOGGING
  exec.consolelog = "/var/log/jail_console_${name}.log";

  # PERMISSIONS
  allow.raw_sockets;
  exec.clean;
  mount.devfs;
  devfs_ruleset = 5;

  # PATH/HOSTNAME
  path = "/usr/local/jails/containers/${name}";
  host.hostname = "${name}";

  # VNET/VIMAGE
  vnet;
  vnet.interface = "${epair}b";

  # ADD TO bridge INTERFACE
  exec.prestart  = "/sbin/ifconfig ${epair} create up";
  exec.prestart += "/sbin/ifconfig ${epair}a up descr jail:${name}";
  exec.prestart += "/sbin/ifconfig ${bridge} addm ${epair}a up";
  exec.start    += "/sbin/ifconfig ${epair}b ${ip} up";
  exec.start    += "/sbin/route add default ${gateway}";
  exec.start  += "/bin/sh /etc/rc";
  exec.stop = "/bin/sh /etc/rc.shutdown";
  exec.poststop = "/sbin/ifconfig ${bridge} deletem ${epair}a";
  exec.poststop += "/sbin/ifconfig ${epair}a destroy";
}
EOF
```

Shut down the VM

## Build and install a DEBUG kernel on the VM

### Start the target VM with a serial console

```sh
qemu-system-x86_64 \
  -m 16G \
  -cpu host \
  -smp 10 \
  -machine q35,accel=kvm \
  -drive file=FreeBSD-14.3-RELEASE-amd64.qcow2,format=qcow2 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -device e1000,netdev=net0,mac=52:54:00:aa:00:01 \
  -serial mon:stdio \
  -nographic \
  -vga none \
  -display none
```

### Log in as root

```
login: root
password: foobar
```

### Compile and install a FreeBSD DEBUG kernel

We'll use the `/usr/src/sys/amd64/conf/GENERIC-DEBUG` kernel configuration but disable assertions as follows:

```sh
cat << 'EOF' >> /usr/src/sys/amd64/conf/GENERIC-DEBUG
nooptions INVARIANTS
nooptions INVARIANT_SUPPORT
EOF
```

Build the DEBUG kernel

```sh
cd /usr/src
make -j8 buildkernel KERNCONF=GENERIC-DEBUG
```

Install the DEBUG kernel

```sh
make installkernel KERNCONF=GENERIC-DEBUG
```

## Install kgdb

```sh
pkg install gdb
```

## Shut down the VM

```sh
poweroff
```

## Copy the disk image for the target VM

```sh
cp FreeBSD-14.3-RELEASE-amd64.qcow2 FreeBSD-14.3-RELEASE-amd64-target.qcow2
```

## Rename the disk image for the debugger VM

```sh
mv FreeBSD-14.3-RELEASE-amd64.qcow2 FreeBSD-14.3-RELEASE-amd64-debugger.qcow2
```

## Reconfigure debugger VM for online debugging of the target VM

```sh
./run_debugger.sh # or ./run_debugger_apple.sh on Apple Silicon
```

### Update `rc.conf`

```sh
cat << 'EOF' > /etc/rc.conf
hostname="prisonbreak-debugger"
sshd_enable="YES"
moused_nondefault_enable="NO"
dumpdev="NO"

# Network to host for internet access
defaultrouter="10.0.2.2"
ifconfig_em0="inet 10.0.2.16/24"

# Network between debugger and target VM to copy kernel image and other files
ifconfig_em1="inet 192.168.100.2/24"
EOF
```

## Update `/boot/loader.conf`

Remove the following lines

```
# Extra serial configuration for console and debugger to co-exist
boot_multicons="YES"
gdb_port="0x2f8"
gdb_debugger="YES"
gdb_enable="YES"
```

### Update `/boot/device.hints`

Remove the following line

```
hint.uart.1.flags="0x90"
```

### Update `sysctl.conf`

```sh
cat << 'EOF' > /etc/sysctl.conf
kern.panic_reboot_wait_time=-1
EOF
```

Reboot the debugger VM

### Start the target VM

```sh
./run.sh # or ./run_apple.sh on Apple Silicon
```

### Start kgdb on the debugger VM

```sh
kgdb -r 10.0.2.2:4444 /usr/lib/debug/boot/kernel/kernel.debug
```

### Enter the debugger on the target VM

```sh
sysctl debug.kdb.enter=1
```

## References

- [FreeBSD Jails](https://docs.freebsd.org/en/books/handbook/jails/)
- Relevant chapter of the FreeBSD Developers' Handbook (of course!): [On-Line Kernel Debugging Using Remote GDB](https://docs.freebsd.org/en/books/developers-handbook/kerneldebug/#kerneldebug-online-gdb)
- [How to Use `kgdb` for Kernel Debugging on FreeBSD Operating System](https://www.siberoloji.com/how-to-use-kgdb-for-kernel-debugging-on-freebsd-operating-system/)
- [FreeBSD kernel debugging](https://census-labs.com/news/2009/01/19/freebsd-kernel-debugging/)
- [kgdb](https://man.freebsd.org/cgi/man.cgi?query=kgdb) FreeBSD kernel debugger
