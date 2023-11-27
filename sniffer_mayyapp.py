# Importing all helper modules
import csv
import socket
import struct
import time

# helper function for experiment
def write_to_csv(count_dic, filename='sniffer_mayyapp.csv'):
    with open(filename, 'w') as file:
        writer = csv.writer(file)
        for key, value in count_dic.items():
            writer.writerow([key, value])

# function to process ip packet
def process_ip_packet(data, count_dic):
    ip_version = data[0] >> 4
    ip_header_length = (data[0] & 15) * 4
    ttl, proto, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    count_dic["ip"] += 1
    return data[ip_header_length:], proto

# function to process tcp packet
def process_tcp_packet(data, count_dic):
    (src_port, dest_port, seq_num, ack, offset_reserved_flags) = struct.unpack("! H H L L H", data[:14])
    count_dic["tcp"] += 1
    if dest_port == 80 or src_port == 80:
        count_dic["http"] += 1
    if dest_port == 443 or src_port == 443:
        count_dic["https"] += 1
    return data[14:]

# function to process udp packet
def process_udp_packet(data, count_dic):
    (src_port2, dst_port2, size) = struct.unpack("! H H 2x H", data[:8])
    count_dic["udp"] += 1
    if dst_port2 == 53 or src_port2 == 53:
        count_dic["dns"] += 1
    if dst_port2 == 80 or dst_port2 == 443 or src_port2 == 80 or src_port2 == 443:
        count_dic["quic"] += 1
    return data[8:]

# start execution
def start():
    count = {"tcp": 0, "udp": 0, "icmp": 0, "ip": 0, "http": 0, "dns": 0, "https": 0, "quic": 0}
    con = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) 
    # Run for 30 seconds
    end_time = time.time() + 30  

    while time.time() < end_time:
        data, address = con.recvfrom(65536)
        dest_mac, src_mac, protocol = struct.unpack("! 6s 6s H", data[:14])
        protocol = socket.htons(protocol)
        data = data[14:]

        if protocol == 8:  # IP packet
            data, proto = process_ip_packet(data, count)

            if proto == 6:  # TCP packet
                data = process_tcp_packet(data, count)

            elif proto == 1:  # ICMP packet
                count["icmp"] += 1

            elif proto == 17:  # UDP packet
                data = process_udp_packet(data, count)

    print("count_dic", count)
    write_to_csv(count)

if __name__ == "__main__":
    start()
