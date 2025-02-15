# Playground

This is my playground for experimenting with Linux namespaces.

## `tun_ping.py`

A Python script that demonstrates network namespace isolation and TUN device manipulation. The script:

- Creates a user namespace with root privileges
- Establishes a network namespace
- Sets up a TUN virtual network interface to handle ICMP (ping) traffic
- Implements a basic IPv4 pseudo-gateway that responds to ICMP Echo Requests with Echo Replies

> **:warning::**
>
> On Ubuntu 23.04+ the following Kernel parameters are required (or the script has to be run as root):
>
> 1. `sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=0`
> 2. `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`

Example:

```bash
$ python3 ./tun_ping.py
Re-executing in a new user namespace...
Operating as ubuntu with uid=0 in new namespace.
Am I root?: YES :)
Cloning into new network namespace...
Creating TUN device...
Created TUN device: tun0
Confguring TUN device...
Executing: ip addr add 192.168.1.1/24 dev tun0
Executing: ip link set tun0 up
Executing: ip route add 0.0.0.0/0 via 192.168.1.1 dev tun0
Configuring done.
Forking...
Parent is acting as gateway.
Acting as a IPv4 pseudo gateway...
Child starts pinging.
[CHILD]: Ping 10.0.0.1
[PARENT]: Received ICMP Packet type 8 code 0 from 192.168.1.1
[PARENT]: Answering with ICMP Echo Reply from 192.168.1.1 to 10.0.0.1
[CHILD]: Reply from 10.0.0.1: time=0.55ms
[CHILD]: Ping 10.0.0.1
[PARENT]: Received ICMP Packet type 8 code 0 from 192.168.1.1
[PARENT]: Answering with ICMP Echo Reply from 192.168.1.1 to 10.0.0.1
[CHILD]: Reply from 10.0.0.1: time=0.02ms
```
