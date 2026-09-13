#!/bin/sh
set -e

ip tuntap add dev tap0 mode tap
ip addr add 172.30.0.1/24 dev tap0
ip link set tap0 up

iptables -t nat -A POSTROUTING -s 172.30.0.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -i tap0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o tap0 -m state --state RELATED,ESTABLISHED -j ACCEPT

exec "$@"