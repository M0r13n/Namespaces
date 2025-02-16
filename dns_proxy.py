#!/usr/bin/env python3
# sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=0
# sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
# unshare --user --map-user=0

import json
import fcntl
import getpass
import os
import select
import socket
import struct
import subprocess
import time
from dataclasses import dataclass

from scipy.fft import dst

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
    uid = os.getuid()
    os.unshare(os.CLONE_NEWUSER)
    uidmap = f"0 {uid} 1"
    with open('/proc/self/uid_map', 'w') as f:
        f.write(uidmap)
    print(f'Operating as {getpass.getuser()} with uid={os.getuid()} in new namespace.')
    print(f'Am I root?: {"YES :)" if os.getuid() == 0 else "NO :("}')


def create_network_namespace():
    print('Cloning into new network namespace...')
    print('You may enter this namespace:')
    print(f'  > sudo nsenter --target {os.getpid()} --net /bin/bash')
    os.unshare(os.CLONE_NEWNET)


def create_tun_device():
    print('Creating TUN device...')
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
    try:
        result = fcntl.ioctl(tun, TUNSETIFF, ifr)
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
    print('Configuring TUN device...')
    run(f"ip addr add {ip_address}/{subnet_mask} dev {tun_name}")
    run(f"ip link set {tun_name} up")
    run(f"ip route add 0.0.0.0/0 via {ip_address} dev {tun_name}")
    print('Configuring done.')


def create_dns_query(domain="www.google.com"):
    """Create a simple DNS query packet."""
    # DNS Header
    transaction_id = os.urandom(2)  # Random transaction ID
    flags = b'\x01\x00'  # Standard query, recursion desired
    questions = b'\x00\x01'  # One question
    answers = b'\x00\x00'    # No answers
    authority = b'\x00\x00'  # No authority RRs
    additional = b'\x00\x00'  # No additional RRs

    # Create DNS question
    labels = domain.split('.')
    question = b''
    for label in labels:
        length = len(label)
        question += bytes([length]) + label.encode()
    question += b'\x00'  # End of domain name

    # Query type (A record) and class (IN)
    qtype = b'\x00\x01'   # A record
    qclass = b'\x00\x01'  # IN class

    # Combine all parts
    packet = (transaction_id + flags + questions + answers +
              authority + additional + question + qtype + qclass)

    return packet


def start_pinging(host: str, port: str):
    """Send DNS queries to Google's public DNS server."""

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        seq = 0

        while seq := seq + 1:
            try:
                print(f'[CHILD]: Sending DNS query {seq} to {host}:{port} from ({sock.getsockname()})')
                query = create_dns_query("heise.de")
                sock.sendto(query, (host, port))

                response, addr = sock.recvfrom(1024)
                print(f"[CHILD]: Received DNS response from {addr[0]}, length: {len(response)} bytes")

            except socket.timeout:
                print("[CHILD]: DNS query timeout")
            except Exception as e:
                print(f"[CHILD]: Error: {e}")

            time.sleep(1)


def handle_packet(data):
    ip_header = IPv4Header.from_bytes(data)

    if len(data) < 28:  # Minimum length for IP + UDP headers
        return None

    ip_header_length = (data[0] & 0xF) * 4
    if data[9] != 17:  # Check if protocol is UDP
        return None

    # Extract UDP header and payload
    udp_data = data[ip_header_length:]
    src_port, dst_port, length, _ = struct.unpack('!HHHH', udp_data[:8])
    payload = udp_data[8:]

    print(f'[PARENT]: Forwarding UDP packet from {ip_header.source_ip}:{src_port} to {ip_header.dest_ip}:{dst_port}')

    return (ip_header.dest_ip, src_port, dst_port, payload)


def act_as_gateway(tun_fd, child_read, child_write):
    print('Acting as a IPv4 pseudo gateway...')
    while True:
        r, _, _ = select.select([tun_fd, child_read], [], [])
        if tun_fd in r:
            data = os.read(tun_fd, 2048)
            if data:
                os.write(child_write, data)
        else:
            response = os.read(child_read, 2048)
            print(IPv4Header.from_bytes(response))
            os.write(tun_fd, response)


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


def make_ip_header(src_ip: str, dst_ip: str, payload_length: int) -> bytes:
    """Create an IP header with given parameters."""
    version_ihl = 0x45  # IPv4, 5 words (20 bytes)
    tos = 0
    total_length = 20 + payload_length  # IP header (20) + payload length
    identification = int.from_bytes(os.urandom(2), 'big')
    flags_fragment = 0x4000  # Don't fragment
    ttl = 64
    protocol = 17  # UDP
    checksum = 0

    # Convert IPs to bytes
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)

    # Pack IP header
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            version_ihl,
                            tos,
                            total_length,
                            identification,
                            flags_fragment,
                            ttl,
                            protocol,
                            checksum,
                            src_ip_bytes,
                            dst_ip_bytes
                            )

    # Calculate and set checksum
    checksum = calculate_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack('!H', checksum) + ip_header[12:]

    return ip_header


def calculate_udp_checksum(src_ip: str, dst_ip: str, udp_packet: bytes) -> int:
    """Calculate UDP checksum including pseudo-header."""
    # Create pseudo-header for checksum calculation
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    zero = 0
    protocol = 17  # UDP protocol number 【1】
    udp_length = len(udp_packet)

    pseudo_header = struct.pack('!4s4sBBH',
                                src_addr,
                                dst_addr,
                                zero,
                                protocol,
                                udp_length
                                )

    # Calculate checksum over pseudo-header + udp packet
    checksum = calculate_checksum(pseudo_header + udp_packet)
    return checksum


def make_udp_header(payload: bytes, src_port: int, dst_port: int) -> bytes:
    """Create a UDP header with correct length and checksum."""
    length = 8 + len(payload)  # 8 bytes for header + payload length 【1】

    # Create initial header with zero checksum
    header = struct.pack('!HHHH',
                         src_port,
                         dst_port,
                         length,
                         0  # Initial checksum of 0
                         )

    return header


def make_response(payload: bytes, src_ip: str, src_port, dst_port, dst_ip: str = "192.168.1.1") -> bytes:
    """Create a complete packet with IP header and payload."""

    # Create UDP header with swapped ports
    udp_header = make_udp_header(payload, src_port, dst_port)

    # Combine UDP header and payload
    udp_packet = udp_header + payload

    # Calculate and set UDP checksum
    checksum = calculate_udp_checksum(src_ip, dst_ip, udp_packet)
    udp_packet = udp_packet[:6] + struct.pack('!H', checksum) + udp_packet[8:]

    # Create IP header
    ip_header = make_ip_header(src_ip, dst_ip, len(udp_packet))

    # Combine headers and payload
    return ip_header + udp_packet


def main():
    re_exec_in_namespace()

    parent_to_child_read, parent_to_child_write = os.pipe()
    child_to_parent_read, child_to_parent_write = os.pipe()

    pid = os.fork()
    if pid > 0:  # Parent process
        try:
            os.close(parent_to_child_read)
            os.close(child_to_parent_write)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)

            while True:
                data = os.read(child_to_parent_read, 1024)
                packet_info = handle_packet(data)
                if packet_info:
                    dst_ip, src_port, dst_port, payload = packet_info
                    try:
                        # Forward the UDP payload
                        sock.sendto(payload, (dst_ip, dst_port))

                        # Wait for response
                        response, addr = sock.recvfrom(1024)
                        if response:
                            foo = make_response(response, dst_ip, dst_port, src_port)
                            os.write(parent_to_child_write, foo)
                    except socket.timeout:
                        print("[PARENT]: No response received")
                    except Exception as e:
                        print(f"[PARENT]: Error: {e}")
        except Exception as e:
            print(f"Error in parent process: {e}")
            os.wait()
    else:
        os.close(parent_to_child_write)
        os.close(child_to_parent_read)

        create_network_namespace()
        tun_fd, tun_name = create_tun_device()
        configure_tun_device(tun_name, TUN_GW_IP, TUN_NET_MASK)

        pid = os.fork()
        if pid > 0:
            print('Parent is acting as gateway.')
            act_as_gateway(tun_fd, parent_to_child_read, child_to_parent_write)
        else:
            print('Child starts UDP pinging.')
            start_pinging('10.0.0.240', 53)


if __name__ == "__main__":
    main()
