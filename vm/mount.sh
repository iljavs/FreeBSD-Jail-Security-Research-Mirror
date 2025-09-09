#!/bin/sh

# With password
# sshfs -o port=2222 \
#       -o PreferredAuthentications=password \
#       -o PubkeyAuthentication=no \
#       -o PasswordAuthentication=yes \
#       root@localhost:/usr/local/jails/containers/prisonbreak/root/src \
#       ./mnt

# With public key
sshfs -o port=2222 \
      root@localhost:/usr/local/jails/containers/prisonbreak/root/src \
      ./mnt
