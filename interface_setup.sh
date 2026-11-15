#!/bin/sh
# this file prepares network interfaces for application operations
# here tap0 is a trunk interface that handles all VLANS inside LAN (avoiding shadowIT)
# and tap0.999 is a promisc on, only listening for mirrored ip frames 

sudo ip link set tap0 up

sudo modprobe 8021q

sudo ip link add link tap0 name tap0.10 type vlan id 10
sudo ip link add link tap0 name tap0.20 type vlan id 20
sudo ip link add link tap0 name tap0.30 type vlan id 30
sudo ip link add link tap0 name tap0.999 type vlan id 999

sudo ip addr add 192.168.10.10/24 dev tap0.10
sudo ip addr add 192.168.20.10/24 dev tap0.20
sudo ip addr add 192.168.30.10/24 dev tap0.30
sudo ip link set tap0.999 promisc on

sudo ip link set dev tap0.10 up
sudo ip link set dev tap0.20 up
sudo ip link set dev tap0.30 up
sudo ip link set dev tap0.999 up
