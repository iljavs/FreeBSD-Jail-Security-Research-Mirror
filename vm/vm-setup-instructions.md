# VM setup instructions

## Create virtual disk

```sh
qemu-img create -f qcow2 FreeBSD-14.3-RELEASE-amd64.qcow2 10G
```

## Fetch installation ISO

```sh
curl -sL https://download.freebsd.org/releases/amd64/amd64/ISO-IMAGES/14.3/FreeBSD-14.3-RELEASE-amd64-bootonly.iso.xz \
  | xz -d > /tmp/FreeBSD-14.3-RELEASE-amd64-bootonly.iso
```

## Boot VM for installation

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

- Distribution Select: keep defaults
- Partitioning: Guided UFS Disk Setup, Entire disk, MBR
- Time Zone: Europe/Belgium
- System Hardening: keep defaults (no extra hardening options enabled)
- Extra users: no need

Shut down VM

## Boot VM for configuration

```sh
qemu-system-x86_64 \
  -M q35 \
  -m 4G \
  -cpu host \
  -smp 4 \
  -machine q35,accel=kvm \
  -drive file=FreeBSD-14.3-RELEASE-amd64.qcow2,format=qcow2 \
  -device e1000,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22
```

## Enable ssh root login for convenience

```sh
sed -i '' 's/^#PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i '' 's/^#PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
service sshd restart
```

## SSH into VM to continue configuration

Connecting to the VM through ssh makes it easier to copy paste the configuration commands that follow. Doing this over a serial console has issues because of lag / buffer / missing characters.

```sh
ssh -p 2222 root@localhost
```

## Configure to boot VM into serial console by default

I prefer interacting with the VM console over serial through my terminal instead of through the graphical VGA output by qemu for everything except configuring the VM.

```sh
cat << 'EOF' > /boot/loader.conf
autoboot_delay=3
console="comconsole"
boot_serial="YES"
EOF
```

## Disable automatic reboot on panic

Give the hacker time to take a screenshot of the spoils.

```sh
cat << 'EOF' >> /etc/sysctl.conf
kern.panic_reboot_wait_time=-1
EOF
```

## Enable jails

See https://docs.freebsd.org/en/books/handbook/jails/

```sh
sysrc jail_enable="YES"
sysrc jail_parallel_start="YES"
```

## Configure bridge for VNET jail

```sh
sysrc defaultrouter="10.0.2.2"
sysrc cloned_interfaces="bridge0"
sysrc ifconfig_bridge0="inet 10.0.2.15/24 addm em0 up"
sysrc ifconfig_em0="up"
```

## Set up jail directory tree

```sh
mkdir /usr/local/jails/
mkdir /usr/local/jails/media
mkdir /usr/local/jails/containers
```

## Fetch userland

```sh
fetch https://download.freebsd.org/ftp/releases/amd64/amd64/14.3-RELEASE/base.txz -o /usr/local/jails/media/14.3-RELEASE-base.txz
```

## Create proof of concept jail

```sh
mkdir -p /usr/local/jails/containers/prisonbreak
tar -xf /usr/local/jails/media/14.3-RELEASE-base.txz -C /usr/local/jails/containers/prisonbreak --unlink
```

## Copy timezone and DNS server files

```sh
cp /etc/resolv.conf /usr/local/jails/containers/prisonbreak/etc/resolv.conf
cp /etc/localtime /usr/local/jails/containers/prisonbreak/etc/localtime
```

## Update to latest patch level

```sh
freebsd-update -b /usr/local/jails/containers/prisonbreak/ fetch install
```

## Configure jails

```sh
cat << 'EOF' > /etc/jail.conf
.include "/etc/jail.conf.d/*.conf";
EOF
```

## Configure proof of concept jail

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

## Shutdown VM

```sh
poweroff
```

# Start VM with serial console

```sh
./run.sh
```

## Enter jail

```sh
jexec -u root prisonbreak
```
