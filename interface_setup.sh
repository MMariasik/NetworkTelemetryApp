#!/bin/sh

sudo ip link set tap0 up
sudo ip link set tap1 up

sudo ip link set tap1 promisc on

sudo modprobe 8021q

sudo ip link add link tap0 name tap0.10 type vlan id 10
sudo ip link add link tap0 name tap0.20 type vlan id 20
sudo ip link add link tap0 name tap0.30 type vlan id 30

sudo ip addr add 192.168.10.10/24 dev tap0.10
sudo ip addr add 192.168.20.10/24 dev tap0.20
sudo ip addr add 192.168.30.10/24 dev tap0.30

sudo ip link set dev tap0.10 up
sudo ip link set dev tap0.20 up
sudo ip link set dev tap0.30 up
