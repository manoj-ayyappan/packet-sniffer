import csv
import socket
import struct
import time

def write_to_csv(count_dic, filename='sniffer_mayyapp.csv'):
    with open(filename, 'w') as file:
        writer = csv.writer(file)
        for key, value in count_dic.items():
            writer.writerow([key, value])

def process_ip_packet(data, count_dic):
    ip_version = data[0] >> 4
    ip_header_length = (data[0] & 15) * 4
    ttl, proto, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    count_dic["ip"] += 1
    return data[ip_header_length:], proto

def process_tcp_packet(data, count_dic):
    (src_port, dest_port, seq_num, ack, offset_reserved_flags) = struct.unpack("! H H L L H", data[:14])
    count_dic["tcp"] += 1
    if dest_port == 80 or src_port == 80:
        count_dic["http"] += 1
    if dest_port == 443 or src_port == 443:
        count_dic["https"] += 1
    return data[14:]

def process_udp_packet(data, count_dic):
    (src_port2, dst_port2, size) = struct.unpack("! H H 2x H", data[:8])
    count_dic["udp"] += 1
    if dst_port2 == 53 or src_port2 == 53:
        count_dic["dns"] += 1
    if dst_port2 == 80 or dst_port2 == 443 or src_port2 == 80 or src_port2 == 443:
        count_dic["quic"] += 1
    return data[8:]

def start():
    count_dic = {"tcp": 0, "udp": 0, "icmp": 0, "ip": 0, "http": 0, "dns": 0, "https": 0, "quic": 0}
    con = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # Raw socket
    end_time = time.time() + 30  # Experiment time 30s

    while time.time() < end_time:
        data, address = con.recvfrom(65536)
        dest_mac, src_mac, protocol = struct.unpack("! 6s 6s H", data[:14])
        protocol = socket.htons(protocol)
        data = data[14:]

        if protocol == 8:  # IP
            data, proto = process_ip_packet(data, count_dic)

            if proto == 6:  # TCP
                data = process_tcp_packet(data, count_dic)

            elif proto == 1:  # ICMP
                count_dic["icmp"] += 1

            elif proto == 17:  # UDP
                data = process_udp_packet(data, count_dic)

    print("count_dic", count_dic)
    write_to_csv(count_dic)

if __name__ == "__main__":
    start()
