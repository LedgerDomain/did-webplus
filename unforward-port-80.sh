#!/bin/bash -e

PROGRAM_NAME=$0

function print_usage_message_and_exit_with_error () {
    echo "Usage: $PROGRAM_NAME <target-port>"
    echo
    echo "UN-forward the forwarding of port 80 (which is the standard port for HTTP) to the given"
    echo "port.  This is how to undo a call to `forward-port-80.sh <target-port>`.  This will invoke"
    echo "'sudo' to run an 'iptables' command, so you will have to enter your password."
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
    echo "****************"
    echo "****************"
    echo "****************"
    echo "NOTE: unforward-port-80.sh script is about to invoke 'sudo iptables -t nat -D OUTPUT -p tcp -d 127.0.0.1 --dport 80 -j REDIRECT --to-ports $TARGET_PORT' so that the previously forwarded port 80 can be undone.  You'll be prompted to enter your password."
    echo "****************"
    echo "****************"
    echo "****************"
    sudo iptables -t nat -D OUTPUT -p tcp -d 127.0.0.1 --dport 80 -j REDIRECT --to-ports $TARGET_PORT
fi
