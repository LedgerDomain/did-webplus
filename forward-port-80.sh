#!/bin/bash -e

PROGRAM_NAME=$0

function print_usage_message_and_exit_with_error () {
    echo "Usage: $PROGRAM_NAME <target-port>"
    echo
    echo "Forward port 80 (which is the standard port for HTTP) to the given port.  This is useful"
    echo "for an HTTP server run by a non-privileged user.  This will invoke 'sudo' to run an"
    echo "'iptables' command, so you will have to enter your password."
    exit 1
}

TARGET_PORT=$1

if [ "$TARGET_PORT" == "" ]; then
    print_usage_message_and_exit_with_error
fi

# Figure out what OS we're running on.  The only allowed OSes are "Linux" and "Darwin" (Mac OS X).
# iptables is Linux-only.  NOTE: If this is needed for Mac OS X, see:
# https://apple.stackexchange.com/questions/206887/macos-x-iptables
KERNEL_NAME=$(uname -s)

if [ "$KERNEL_NAME" == "Linux" ]; then
    # This only has to be done once per reboot.  If you want to make this permanent, see:
    # https://linuxconfig.org/how-to-make-iptables-rules-persistent-after-reboot-on-linux
    echo "****************"
    echo "****************"
    echo "****************"
    echo "NOTE: forward-port-80.sh script is about to invoke 'sudo iptables -t nat -I OUTPUT -p tcp -d 127.0.0.1 --dport 80 -j REDIRECT --to-ports $TARGET_PORT' so that this binary can bind to privileged network ports.  You'll be prompted to enter your password."
    echo "****************"
    echo "****************"
    echo "****************"
    sudo iptables -t nat -I OUTPUT -p tcp -d 127.0.0.1 --dport 80 -j REDIRECT --to-ports $TARGET_PORT
fi
