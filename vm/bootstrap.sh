#!/bin/sh

printf "Fetching FreeBSD 14.3 qcow2 disk image..."
curl -sL https://download.freebsd.org/releases/VM-IMAGES/14.3-RELEASE/amd64/Latest/FreeBSD-14.3-RELEASE-amd64.qcow2.xz \
  | xz -d > FreeBSD-14.3-RELEASE-amd64.qcow2

cat << 'OUTER'
done

Follow these instructions to enable serial console output by default:

* Boot the machine with ./run.sh
* Hit 5 and RETURN to force serial console output
* Log in as root and paste the following command to enable serial boot by default:

cat << 'EOF' > /boot/loader.conf
autoboot_delay=3
console="comconsole"
boot_serial="YES"
EOF

Reboot the vm and it should now output to serial console by default.

OUTER
