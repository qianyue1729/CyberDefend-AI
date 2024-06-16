
from packet_sniffer import PacketSniffer
from network_detection_model import NetworkDetectionModel
import csv
from datetime import datetime
import socket
import os
import pandas as pd
from util import block_ip, alert_ip


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))


ALLOW = ['Normal']

ALERT = ['Analysis', 'Port Scan', 'Reconnaissance']

BLOCK = [
    'Backdoor',
    'Bot',
    'DDoS',
    'DoS',
    'DoS GoldenEye',
    'DoS Hulk',
    'DoS SlowHTTPTest',
    'DoS Slowloris',
    'Exploits',
    'FTP Patator',
    'Fuzzers',
    'Generic',
    'Heartbleed',
    'Infiltration',
    'SSH Patator',
    'Shellcode',
    'Web Attack - Brute Force',
    'Web Attack - SQL Injection',
    'Web Attack - XSS',
    'Worms'
]


def get_domain_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ''


def count_blocks_in_last_hour(ip):
    log_file_path = os.path.join(SCRIPT_DIR, 'log_data/log.csv')
    log_df = pd.read_csv(log_file_path)

    # Filter the rows where the source IP is the given IP and the status is 'BLOCK'
    ip_blocks = log_df[(log_df['source_ip'] == ip) &
                       (log_df['status'] == 'BLOCK')]

    # Convert the 'date' column to datetime
    ip_blocks['date'] = pd.to_datetime(ip_blocks['date'])

    # Filter the rows in the last hour
    ip_blocks_last_hour = ip_blocks[ip_blocks['date']
                                    > datetime.now() - pd.Timedelta(hours=1)]

    # Return the count of rows
    return len(ip_blocks_last_hour)


def main():
    packet_sniffer = PacketSniffer()
    network_detection = NetworkDetectionModel()

    log_file_path = os.path.join(SCRIPT_DIR, 'log_data/log.csv')
    log_file = open(log_file_path, 'a', newline='')
    log_writer = csv.writer(log_file)

    unique_addr_file_path = os.path.join(SCRIPT_DIR, 'log_data/unique.csv')
    unique_addr_file = open(unique_addr_file_path, 'a', newline='')
    unique_addr_writer = csv.writer(unique_addr_file)

    unique_addr = pd.read_csv(unique_addr_file_path)
    blocked_ips = unique_addr.loc[unique_addr['status']== 'blocked', 'source_ip'].tolist()

    # Create a set to store unique addresses
    unique_addresses = set(unique_addr['source_ip'].tolist())

    while True:
        data = packet_sniffer.sniffer()
        if data == None:
            continue

        formatted_data, flow_info, source_port, destination_port, source_ip, destination_ip = data
        if source_ip == packet_sniffer.host or source_ip in blocked_ips:
            continue

        prediction = network_detection.predict(formatted_data)
        date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # domain = get_domain_name(source_ip)
        domain = ''
        if prediction in ALLOW:
            log_writer.writerow(
                [
                    date,
                    domain,
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                    'ALLOW',
                    prediction
                ]
            )
            log_file.flush()

            if source_ip not in unique_addresses:
                unique_addr_writer.writerow([date,domain,source_ip,'ALLOW'])
                unique_addresses.add(source_ip)
                unique_addr_file.flush()

        elif prediction in ALERT:
            # alert(ip)
            log_writer.writerow(
                [
                    date,
                    domain,
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                    'ALERT',
                    prediction
                ]
            )
            log_file.flush()

            if source_ip not in unique_addresses:
                unique_addr_writer.writerow([date,domain,source_ip,'ALERT'])
                unique_addresses.add(source_ip)
                unique_addr_file.flush()

        elif prediction in BLOCK:
            log_writer.writerow(
                [
                    date,
                    domain,
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                    'BLOCK',
                    prediction
                ]
            )
            log_file.flush()

            if count_blocks_in_last_hour(source_ip) >= 3:
                # block_ip(source_ip)
                unique_addresses.add(source_ip)
                if source_ip not in unique_addresses:
                    unique_addr_writer.writerow([date, domain, source_ip, 'BLOCK'])
                    unique_addr_file.flush()
                else:
                    unique_addr_df = pd.read_csv(unique_addr_file_path)
                    unique_addr_df.loc[unique_addr_df['source_ip'] == source_ip, 'status'] = 'BLOCK'
                    unique_addr_df.to_csv(unique_addr_file_path, index=False)


if __name__ == "__main__":
    main()
