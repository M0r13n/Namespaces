#!/usr/bin/env python3
# sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=0
# sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
# unshare --user --map-user=0

import fcntl
import getpass
import os
import select
import socket
import struct
import subprocess
import time
from dataclasses import dataclass

TUNSETIFF = 0x400454ca      # TUN/TAP device ioctl code
IFF_TUN = 0x0001            # TUN device (no Ethernet headers)
IFF_NO_PI = 0x1000          # Don't provide packet info
TUN_GW_IP = '192.168.1.1'   # The IP address of the TUN "gateway"
TUN_NET_MASK = '24'         # The subnet mask of the virtual TUN network


@dataclass
class IPv4Header:
    version: int
    ihl: int
    tos: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    header_checksum: int
    source_ip: str
    dest_ip: str

    @classmethod
    def from_bytes(cls, data: bytes) -> 'IPv4Header':
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        return cls(
            version=ip_header[0] >> 4,
            ihl=ip_header[0] & 0xF,
            tos=ip_header[1],
            total_length=ip_header[2],
            identification=ip_header[3],
            flags=ip_header[4] >> 13,
            fragment_offset=ip_header[4] & 0x1FFF,
            ttl=ip_header[5],
            protocol=ip_header[6],
            header_checksum=ip_header[7],
            source_ip=socket.inet_ntoa(ip_header[8]),
            dest_ip=socket.inet_ntoa(ip_header[9])
        )


def re_exec_in_namespace():
    print('Re-executing in a new user namespace...')

    # Get current user ID
    uid = os.getuid()

    # Create new user namespace
    os.unshare(os.CLONE_NEWUSER)

    # Create user mapping
    uidmap = f"0 {uid} 1"
    with open('/proc/self/uid_map', 'w') as f:
        f.write(uidmap)

    print(f'Operating as {getpass.getuser()} with uid={os.getuid()} in new namespace.')
    print(f'Am I root?: {"YES :)" if os.getuid() == 0 else "NO :("}')


def create_network_namespace():
    # This only works for root. This is why re_exec_in_namespace has to be called ealier
    print('Cloning into new network namespace...')
    os.unshare(os.CLONE_NEWNET)


def create_tun_device():
    # This will only work in a dedicated network namespace (where I am root)
    print('Creating TUN device...')
    tun = os.open("/dev/net/tun", os.O_RDWR)

    # Prepare the struct for the ioctl call
    ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)

    try:
        # Call ioctl and get the response
        result = fcntl.ioctl(tun, TUNSETIFF, ifr)

        # Unpack the response to get the interface name
        ifname = struct.unpack('16sH', result)[0].strip(b'\x00').decode('utf-8')

        print(f'Created TUN device: {ifname}')
        return tun, ifname
    except IOError as e:
        os.close(tun)
        raise e


def run(cmd: str, stderr=None, stdout=None):
    print(f'Executing: {cmd}')
    return subprocess.run(cmd.split(), check=True, stderr=stderr, stdout=stdout)


def configure_tun_device(tun_name, ip_address, subnet_mask):
    """Configure the TUN device with an IP address and bring it up."""
    print('Confguring TUN device...')
    run(f"ip addr add {ip_address}/{subnet_mask} dev {tun_name}")
    run(f"ip link set {tun_name} up")
    run(f"ip route add 0.0.0.0/0 via {ip_address} dev {tun_name}")
    print('Configuring done.')


def ping(host):
    # Execute ping command
    run(f"ping {host} -W 1", stdout=os.open('/dev/null', os.O_RDWR))


def start_pinging(host: str):
    # Create and start a separate process for pinging
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.settimeout(2)  # 1 second timeout
        seq = 0

        while seq := seq + 1:
            print(f'[CHILD]: Ping {host}')
            # Send ICMP echo request
            packet = create_icmp_request_packet(seq)
            sock.sendto(packet, (host, 1))

            # Wait for response
            start_time = time.time()
            _, addr = sock.recvfrom(1024)
            end_time = time.time()

            duration = (end_time - start_time) * 1000

            print(f"[CHILD]: Reply from {addr[0]}: time={duration:.2f}ms")
            time.sleep(1)


def create_icmp_request_packet(sequence: int = 0, data: bytes = b"Hello, World!"):
    """Create an ICMP echo request"""
    type = 8  # Echo request
    code = 0
    checksum = 0
    identifier = 1337

    # Create header without checksum first
    header = struct.pack('!BBHHH', type, code, checksum, identifier, sequence)

    # Calculate checksum
    checksum = calculate_checksum(header + data)

    # Create header with checksum and combine with data
    header = struct.pack('!BBHHH', type, code, checksum, identifier, sequence)
    return header + data


def create_icmp_response(original_packet, ip_header_length):
    """Create an ICMP response packet based on the received packet."""
    # Extract original IP header fields
    src_ip = original_packet[12:16]  # Source IP from original packet
    dst_ip = original_packet[16:20]  # Destination IP from original packet

    # Create IP header
    ip_version_ihl = original_packet[0]  # Copy version and IHL
    ip_tos = original_packet[1]          # Copy TOS
    ip_total_length = original_packet[2:4]
    ip_id = os.urandom(2)               # New random ID
    ip_flags_offset = b'\x00\x00'       # No flags or fragment offset
    ip_ttl = b'\x40'                    # TTL 64
    ip_protocol = b'\x01'               # ICMP protocol
    ip_checksum = b'\x00\x00'           # Initial checksum (will calculate later)

    # Swap source and destination IPs for response
    ip_header = struct.pack('!B', ip_version_ihl) + bytes([ip_tos]) + ip_total_length + \
        ip_id + ip_flags_offset + ip_ttl + ip_protocol + ip_checksum + \
        dst_ip + src_ip

    # Create ICMP reply header
    icmp_checksum = b'\x00\x00'
    icmp_type = b'\x00'
    icmp_code = b'\x00'
    icmp_id = original_packet[ip_header_length + 4:ip_header_length + 6]    # Copy original ID
    icmp_seq = original_packet[ip_header_length + 6:ip_header_length + 8]   # Copy original sequence

    # Copy the data from original packet
    icmp_data = original_packet[ip_header_length + 8:]

    # Construct ICMP packet
    icmp_packet = icmp_type + icmp_code + icmp_checksum + icmp_id + icmp_seq + icmp_data

    # Calculate ICMP checksum
    icmp_checksum = calculate_checksum(icmp_packet)
    icmp_packet = icmp_type + icmp_code + struct.pack('!H', icmp_checksum) + \
        icmp_id + icmp_seq + icmp_data

    # Calculate IP header checksum
    ip_checksum = calculate_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]

    print(f'[PARENT]: Answering with ICMP Echo Reply from {socket.inet_ntoa(src_ip)} to {socket.inet_ntoa(dst_ip)}')

    return ip_header + icmp_packet


def calculate_checksum(data):
    """Calculate Internet Checksum."""
    if len(data) % 2 == 1:
        data += b'\x00'

    words = struct.unpack('!%dH' % (len(data) // 2), data)
    checksum = sum(words)

    high = checksum >> 16
    while high:
        checksum = (checksum & 0xFFFF) + high
        high = checksum >> 16

    return ~checksum & 0xFFFF


def handle_packet(tun_fd, data):
    """Handle received packet and write response to TUN device."""
    # Parse IPv4 header
    ip_header = IPv4Header.from_bytes(data)

    # Ensure it's an ICMP Echo Request
    if len(data) < 28:  # Minimum length for IP + ICMP headers
        return

    ip_header_length = (data[0] & 0x0F) * 4
    if data[9] != 1:  # Check if protocol is ICMP
        return

    icmp_type = data[ip_header_length]
    if icmp_type != 8:  # Check if it's an Echo Request
        return

    icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', data[20:28])
    print(f'[PARENT]: Received ICMP Packet type {icmp_type} code {icmp_code} from {ip_header.source_ip}')

    # Create and send response
    response = create_icmp_response(data, ip_header_length)
    os.write(tun_fd, response)


def act_as_gateway(tun_fd):
    # Read packets from the TUN device and answer with ICMP Echo Replies
    print('Acting as a IPv4 pseudo gateway...')
    while True:
        r, _, _ = select.select([tun_fd], [], [])
        if tun_fd in r:
            data = os.read(tun_fd, 2048)
            handle_packet(tun_fd, data)


def fork(tun_fd: int):
    print('Forking...')
    pid = os.fork()
    if pid > 0:
        print('Parent is acting as gateway.')
        act_as_gateway(tun_fd)
    else:
        print('Child starts pinging.')
        start_pinging('10.0.0.1')


def main():
    re_exec_in_namespace()
    create_network_namespace()
    tun_fd, tun_name = create_tun_device()
    configure_tun_device(tun_name, TUN_GW_IP, TUN_NET_MASK)
    fork(tun_fd)


if __name__ == "__main__":
    main()
