#!/bin/sh

# With password
# ssh -o PreferredAuthentications=password \
#     -o PubkeyAuthentication=no \
#     -o PasswordAuthentication=yes \
#     root@localhost \
#     -t \
#     -p 2222 \
#     jexec prisonbreak /bin/tcsh

# With public key
ssh root@localhost \
    -t \
    -p 2222 \
    jexec prisonbreak /bin/tcsh
