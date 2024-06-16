import struct
import socket
import textwrap
import os
import time
from typing import Dict, Tuple

BUFFER_SIZE = 65536
NUMBER_OF_TENSOR = 512
TCP_PROTOCOL_NUMBER = 6
DATA_SEPARATOR = '-1'

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t'
DATA_TAB_2 = '\t\t'
DATA_TAB_3 = '\t\t\t'
DATA_TAB_4 = '\t\t\t\t'


class PacketSniffer:
    def __init__(self):
        self.host = socket.gethostbyname(socket.gethostname())
        self.socket_protocol = socket.IPPROTO_IP if os.name == "nt" else socket.IPPROTO_ICMP
        self.connection = self.__create_connection()
        self.forward_packets = 0
        self.backward_packets = 0
        self.forward_bytes = 0
        self.backward_bytes = 0
        self.start_time = time.time()

    def __create_connection(self):
        connection = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, self.socket_protocol)
        connection.bind((self.host, 0))
        connection.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if os.name == "nt":
            connection.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        return connection

    def sniffer(self):

        raw_data, address = self.connection.recvfrom(BUFFER_SIZE)
        ip_header, ip_data = self.__ip_data_extractor(raw_data)

        if ip_header['protocol'] == TCP_PROTOCOL_NUMBER:
            tcp_header, tcp_data = self.__tcp_data_extractor(ip_data)

            flow_info, self.forward_packets, self.backward_packets, self.forward_bytes, self.backward_bytes = self.__calculate_flow_rates(
                ip_header,
                self.host, self.start_time,
                self.forward_packets,
                self.backward_packets,
                self.forward_bytes,
                self.backward_bytes
            )

            formatted_data = self.__format_data(
                flow_info,
                tcp_header,
                ip_header,
                tcp_data
            )

            # formatted_data = formatted_data[:NUMBER_OF_TENSOR]
            formatted_data = ' '.join(map(str, formatted_data))

            self.print_ip_data(ip_header)
            self.print_tcp_data(tcp_header, tcp_data)
            # print(formatted_data)
            print('\n\n\n')

            return (
                formatted_data,
                flow_info,
                tcp_header['source_port'],
                tcp_header['destination_port'],
                self.__format_ipv4(ip_header['source']),
                self.__format_ipv4(ip_header['destination'])
            )

        # if os.name == "nt":
        #     self.connection.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    def __ip_data_extractor(self, data: bytes) -> Tuple[Dict[str, int], bytes]:
        version_header_len, tos, total_len, ttl, protocol, src, dst = struct.unpack(
            "! B B H 4x B B 2x 4s 4s", data[:20])
        # these number is base on ip bit offset
        version = version_header_len >> 4
        header_len = (version_header_len & 15) * 4
        return {
            'version': version,
            'header_length': header_len,
            'tos': tos,
            'total_length': total_len,
            'ttl': ttl,
            'protocol': protocol,
            'source': src,
            'destination': dst,
        }, data[header_len:]

    def __tcp_data_extractor(self, data: bytes) -> Tuple[Dict[str, int], bytes]:
        src_port, dst_port, offset_reserve_flag = struct.unpack(
            "! H H 8x H", data[:14])
        # these number is base on TCP bit offset
        offset = (offset_reserve_flag >> 12) * 4
        flag_urg = (offset_reserve_flag & 32) >> 5
        flag_ack = (offset_reserve_flag & 16) >> 4
        flag_psh = (offset_reserve_flag & 8) >> 3
        flag_rst = (offset_reserve_flag & 4) >> 2
        flag_syn = (offset_reserve_flag & 2) >> 1
        flag_fin = offset_reserve_flag & 1
        return {
            'source_port': src_port,
            'destination_port': dst_port,
            'offset': offset,
            'flag_urg': flag_urg,
            'flag_ack': flag_ack,
            'flag_psh': flag_psh,
            'flag_rst': flag_rst,
            'flag_syn': flag_syn,
            'flag_fin': flag_fin,
        }, data[offset:]

    def __format_ipv4(self, ipv4_addr):
        return '.'.join(map(str, ipv4_addr))

    def __format_multi_line(self, prefix, string, size=80):
        size -= len(prefix)
        if size % 2:
            size -= 1
        if isinstance(string, bytes):
            string = ' '.join(f'{byte:d}' for byte in string)
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

    def __format_data(self,
                      flow_info,
                      tcp_header,
                      ip_header,
                      tcp_data):
        # this format is base on format data for AI model in 'static' folder
        formatted_data = [
            int(flow_info['fpps']),
            int(flow_info['bpps']),
            int(flow_info['btps']),
            DATA_SEPARATOR,
            str(tcp_header['source_port']),
            str(tcp_header['destination_port']),
            str(ip_header['total_length']),
            str(len(tcp_data)),
            str(ip_header['ttl']),
            str(ip_header['tos']),
            str(tcp_header['offset']),
            str(tcp_header['flag_urg'] |
                tcp_header['flag_ack'] << 1 |
                tcp_header['flag_psh'] << 2 |
                tcp_header['flag_rst'] << 3 |
                tcp_header['flag_syn'] << 4 |
                tcp_header['flag_fin'] << 5
                )
        ]

        raw_bytes = [str(byte) for byte in tcp_data]

        formatted_data.append(DATA_SEPARATOR)
        formatted_data.extend(raw_bytes)

        return formatted_data

    def print_ip_data(self, ip_header):
        print(f"{TAB_1}IPV4 Packet:")
        print(
            f"{TAB_2}Version: {ip_header['version']}, Header Length: {ip_header['header_length']}")
        print(f"{TAB_2}Type of Service: {ip_header['tos']}")
        print(f"{TAB_2}Total Length: {ip_header['total_length']}")
        print(f"{TAB_2}Time to Live: {ip_header['ttl']}")
        print(f"{TAB_2}Protocol: {ip_header['protocol']}")
        print(f"{TAB_2}Source: {self.__format_ipv4(ip_header['source'])}")
        print(
            f"{TAB_2}Destination: {self.__format_ipv4(ip_header['destination'])}")

    def print_tcp_data(self, tcp_header, tcp_data):
        print(f"{TAB_1}TCP Segment:")
        print(
            f"{TAB_2}Source Port: {tcp_header['source_port']}, Destination Port: {tcp_header['destination_port']}")
        print(f"{TAB_2}offset: {tcp_header['offset']}")
        print(f"{TAB_2}Flags:")
        print(f"{TAB_3}URG: {tcp_header['flag_urg']}, ACK: {tcp_header['flag_ack']}, PSH: {tcp_header['flag_psh']}, RST: {tcp_header['flag_rst']}, SYN: {tcp_header['flag_syn']}, FIN:{tcp_header['flag_fin']}")
        print(f"{TAB_2}Data:")
        print(self.__format_multi_line(DATA_TAB_3, tcp_data))

    def __calculate_flow_rates(self,
                               ip_header: Dict[str, int],
                               host: str, start_time: float,
                               forward_packets: int,
                               backward_packets: int,
                               forward_bytes: int,
                               backward_bytes: int) -> Tuple[Dict[str, float], int, int, int, int]:

        if self.__format_ipv4(ip_header['source']) == host:
            forward_packets += 1
            forward_bytes += ip_header["total_length"]
        elif self.__format_ipv4(ip_header['destination']) == host:
            backward_packets += 1
            backward_bytes += ip_header["total_length"]

        current_time = time.time()
        elapsed_time = current_time - start_time  # in seconds

        backward_forward_bytes = backward_bytes + forward_bytes

        forward_packets_per_second = forward_packets / elapsed_time
        backward_packets_per_second = backward_packets / elapsed_time
        bytes_transferred_per_second = backward_forward_bytes / elapsed_time

        return {
            'fpps': forward_packets_per_second,
            'bpps': backward_packets_per_second,
            'btps': bytes_transferred_per_second
        }, forward_packets, backward_packets, forward_bytes, backward_bytes
