import socket
import struct
import argparse
import time
import sys

ICMP_REQUEST = 8
ICMP_REPLY = 0

def create_ip_header(src, dst, payload):
    version = 4
    header_len = 5
    tos = 0
    total_len = header_len*4 + len(payload)
    id = 10845
    flag = 0
    fragment_offset = 0
    ttl = 128
    protocol = socket.IPPROTO_ICMP
    checksum_value = 0
    src_addr = socket.inet_aton(src)
    dst_addr = socket.inet_aton(dst)

    ip_header = struct.pack(">BBHHHBBH4s4s", 
                            (version << 4) + header_len,
                            tos,
                            total_len,
                            id,
                            (flag << 13) + fragment_offset,
                            ttl,
                            protocol,
                            checksum_value,
                            src_addr,
                            dst_addr)
    
    checksum_value = checksum(ip_header)

    ip_header = struct.pack(">BBHHHBBH4s4s", 
                            (version << 4) + header_len,
                            tos,
                            total_len,
                            id,
                            (flag << 13) + fragment_offset,
                            ttl,
                            protocol,
                            checksum_value,
                            src_addr,
                            dst_addr)
    
    return ip_header + payload


def create_icmp(payload, icmp_type, packet_number):
    type = icmp_type
    code = 0
    checksum_value = 0
    id = 1
    seq = packet_number + 1
    payload = payload.encode()

    icmp_header = struct.pack(">BBHHH",
                              type,
                              code,
                              checksum_value,
                              id,
                              seq)
    
    checksum_value = checksum(icmp_header + payload)

    icmp_header = struct.pack(">BBHHH",
                              type,
                              code,
                              checksum_value,
                              id,
                              seq)
    
    return icmp_header + payload


def checksum(data):
    if (len(data) % 2 != 0):
        data += b'\x00'

    sum = 0
    for i in range (0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        sum += w
        if (sum > 0xFFFF):
            sum = (sum & 0xFFFF) + 1

    checksum = 0xFFFF - sum
    return checksum


def get_info(packet):
    ip_header_len = (packet[0] & 0x0F) * 4
    total_len = struct.unpack(">H", packet[2:4])[0]
    icmp_header_len = 8

    message_len = total_len - ip_header_len - icmp_header_len
    ttl = packet[8]

    return (message_len, ttl)


def handle_arg():
    parser = argparse.ArgumentParser(usage="""Ping program make by me to learn computer networking\n python ping.py [option] <destination>\n\nEx:\n    python ping.py 192.168.1.1\n    python ping.py -n 5 google.com""")
    parser.add_argument("-n", type=int, default=1, help="Number of packet to send")
    parser.add_argument("dst", help="Destination host (hostname or ip address)")
    args = parser.parse_args()

    number_of_packet = args.n
    try:
        dest_addr = socket.gethostbyname(args.dst)

    except socket.gaierror:
        print(f"Ping request could not find host {args.dst}. Please check the name and try again.")
        sys.exit(1)

    return (number_of_packet, dest_addr)


def create_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.settimeout(5)

    return s


def get_physical_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    src = s.getsockname()[0]
    s.close()

    return src


def create_packet(destination_addr, packet_number):
    src = get_physical_address();
    dst = destination_addr
    message = "Goodbye, world!"

    icmp_packet = create_icmp(message, ICMP_REQUEST, packet_number)
    ip_packet = create_ip_header(src, dst, icmp_packet)

    return ip_packet


def send(packet, socket_to_send, address_to_send):
    send_time = time.time()
    socket_to_send.sendto(packet, (address_to_send, 0))

    try:
        reply_packet = socket_to_send.recv(1024)
        receive_time = time.time()

        rtt = round((receive_time - send_time) * 1000)
        if (rtt < 1):
            delay = "time<1ms"
        else:
            delay = f"time={rtt}ms" 

        info = get_info(reply_packet)
        print(f"Reply from {address_to_send}: bytes={info[0]} {delay} TTL={info[1]}")
        

    except TimeoutError:
        print("Request timed out.")
        print(socket.inet_ntoa(packet[12:16]))
        print(socket.gethostbyname_ex(socket.gethostname()))

    
def send_icmp_packet(number_of_packet, destination_addr):
    s = create_socket()

    try:
        for i in range(number_of_packet):
            packet = create_packet(destination_addr, i)
            send(packet, s, destination_addr)
            time.sleep(1)

    except KeyboardInterrupt:
        print("Program exiting...")


if __name__ == "__main__":
    number_of_packet, dst_addr = handle_arg()

    send_icmp_packet(number_of_packet, dst_addr)
