#!/bin/sh
set -e

IFACE=eth0
BRIDGE=br0

IP_CIDR=$(ip -4 addr show $IFACE | grep inet | awk '{print $2}')
GATEWAY=$(ip route | grep default | awk '{print $3}')

ip link add $BRIDGE type bridge
ip addr flush dev $IFACE
ip link set $IFACE master $BRIDGE

ip tuntap add dev tap0 mode tap
ip link set tap0 master $BRIDGE

ip link set $IFACE up
ip link set tap0 up
ip link set $BRIDGE up

ip addr add $IP_CIDR dev $BRIDGE
ip route add default via $GATEWAY dev $BRIDGE

tcpdump -i tap0 -U -w /tmp/boot_capture.pcap &

exec "$@"