"""
AI Usage Statement (Han Chen)
Tools Used: ChatGPT 
    - Usage: Parsing the attack window based on Article's table
    - Verification: Checked the accuracy of the parsed info. Fixed some error.
Prohibited Use Compliance: Confirmed

The full dataset was about 450G, so we decided to only use Friday 02-03-2018 and Friday 23-02-2018.

After the CICFlowMeter generated the data for the traffic flow based on the pcap files, the flow data does not include labels.
This script labels each flow with Benign or its attack type based on the attacking table given in the documentation of the dataset.
"""

import os
import pandas as pd
from datetime import datetime

#flow_root = r"D:\CSEC520-Project\Original Network Traffic and Log data\Friday_Only\flow"
flow_root = r"D:\CSEC520-Project\Original Network Traffic and Log data\Thursday-22-02-2018\flow"
flow_labeled_root = r"D:\CSEC520-Project\CSEC520-FinalProject\CICFlowmeter_Processed_flow_labeled"
os.makedirs(flow_labeled_root, exist_ok=True)

#final_output_csv = os.path.join(flow_labeled_root, "Friday_Full_Labeled.csv")
final_output_csv = os.path.join(flow_labeled_root, "Thursday_220218_Labeled.csv")

attack_windows = [
    {
        "attack_name": "DoS-SlowHTTPTest",
        "attacker_ips": ["13.59.126.31", "172.31.70.23"],
        "victim_ips": ["172.31.69.25", "18.217.21.148"],
        "day": "Fri-16-02-2018",
        "start_time": "10:12",
        "end_time": "11:08"
    },
    {
        "attack_name": "DoS-Hulk",
        "attacker_ips": ["172.31.70.16", "18.219.193.20"],
        "victim_ips": ["172.31.69.25", "18.217.21.148"],
        "day": "Fri-16-02-2018",
        "start_time": "13:45",
        "end_time": "14:19"
    },
    {
        "attack_name": "Brute Force -Web",
        "attacker_ips": ["18.218.115.60"],
        "victim_ips": ["172.31.69.28", "18.218.83.150"],
        "day": "Fri-23-02-2018",
        "start_time": "10:03",
        "end_time": "11:03"
    },
    {
        "attack_name": "Brute Force -XSS",
        "attacker_ips": ["18.218.115.60"],
        "victim_ips": ["172.31.69.28", "18.218.83.150"],
        "day": "Fri-23-02-2018",
        "start_time": "13:00",
        "end_time": "14:10"
    },
    {
        "attack_name": "SQL Injection",
        "attacker_ips": ["18.218.115.60"],
        "victim_ips": ["172.31.69.28", "18.218.83.150"],
        "day": "Fri-23-02-2018",
        "start_time": "15:05",
        "end_time": "15:18"
    },
    {
        "attack_name": "Bot",
        "attacker_ips": ["18.219.211.138"],
        "victim_ips": [
            "18.217.218.111", "18.222.10.237", "18.222.86.193", "18.222.62.221",
            "13.59.9.106", "18.222.102.2", "18.219.212.0", "18.216.105.13",
            "18.219.163.126", "18.216.164.12", "172.31.69.23", "172.31.69.17",
            "172.31.69.14", "172.31.69.12", "172.31.69.10", "172.31.69.8",
            "172.31.69.6", "172.31.69.26", "172.31.69.29", "172.31.69.30"
        ],
        "day": "Fri-02-03-2018",
        "start_time": "10:11",
        "end_time": "11:34"
    },
    {
        "attack_name": "Bot",
        "attacker_ips": ["18.219.211.138"],
        "victim_ips": [
            "18.217.218.111", "18.222.10.237", "18.222.86.193", "18.222.62.221",
            "13.59.9.106", "18.222.102.2", "18.219.212.0", "18.216.105.13",
            "18.219.163.126", "18.216.164.12", "172.31.69.23", "172.31.69.17",
            "172.31.69.14", "172.31.69.12", "172.31.69.10", "172.31.69.8",
            "172.31.69.6", "172.31.69.26", "172.31.69.29", "172.31.69.30"
        ],
        "day": "Fri-02-03-2018",
        "start_time": "14:24",
        "end_time": "15:55"
    },
    {
        "attack_name": "Infiltration",
        "attacker_ips": ["13.58.225.34"],
        "victim_ips": [
            "18.221.148.137", "172.31.69.24"
        ],
        "day": "Wed-28-02-2018",
        "start_time": "13:42",
        "end_time": "14:40"
    },
    {
        "attack_name": "Infiltration",
        "attacker_ips": ["13.58.225.34"],
        "victim_ips": [
            "18.221.148.137", "172.31.69.24"
        ],
        "day": "Wed-28-02-2018",
        "start_time": "10:50",
        "end_time": "12:05"
    },
    {
        "attack_name": "Brute_Force_Web",
        "attacker_ips": ["18.218.115.60"],
        "victim_ips": [
            "18.218.83.150", "172.31.69.28"
        ],
        "day": "Thurs-22-02-2018",
        "start_time": "10:17",
        "end_time": "11:24"
    },
    {
        "attack_name": "Brute_Force_XSS",
        "attacker_ips": ["18.218.115.60"],
        "victim_ips": [
            "18.218.83.150", "172.31.69.28"
        ],
        "day": "Thurs-22-02-2018",
        "start_time": "13:50",
        "end_time": "14:29"
    },
    {
        "attack_name": "SQL_Injection",
        "attacker_ips": ["18.218.115.60"],
        "victim_ips": [
            "18.218.83.150", "172.31.69.28"
        ],
        "day": "Thurs-22-02-2018",
        "start_time": "16:15",
        "end_time": "16:29"
    }
]

def label_flow(row):
    src_ip = row['Src IP']
    dst_ip = row['Dst IP']
    timestamp = row['Timestamp']

    if pd.isna(timestamp):
        return "Benign"

    # date_str = timestamp.strftime("Fri-%d-%m-%Y")
    date_str = timestamp.strftime("Thurs-%d-%m-%Y")


    time_obj = timestamp.time()

    for attack in attack_windows:
        if attack['day'] != date_str:
            continue
        if not (src_ip in attack['attacker_ips'] or dst_ip in attack['attacker_ips']):
            continue
        if not (src_ip in attack['victim_ips'] or dst_ip in attack['victim_ips']):
            continue

        attack_start = datetime.strptime(attack['start_time'], "%H:%M").time()
        attack_end = datetime.strptime(attack['end_time'], "%H:%M").time()

        if attack_start <= time_obj <= attack_end:
            return attack['attack_name']
    
    return "Benign"

all_flows = []

for day_folder in os.listdir(flow_root):
    day_path = os.path.join(flow_root, day_folder)
    if not os.path.isdir(day_path):
        continue

    print(f"Processing day: {day_folder}")

    for flow_csv in os.listdir(day_path):
        if not flow_csv.endswith('.csv'):
            continue

        csv_path = os.path.join(day_path, flow_csv)
        df = pd.read_csv(csv_path)

        df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%d/%m/%Y %I:%M:%S %p', errors='coerce')

        if 'Label' not in df.columns:
            df['Label'] = 'No Label'

        df['Label'] = df.apply(label_flow, axis=1)
        print(f"Processed file: {flow_csv}")
        all_flows.append(df)

print("Merging all together...")

full_dataset = pd.concat(all_flows, ignore_index=True)

full_dataset.to_csv(final_output_csv, index=False)

print(f"Full labeled dataset saved to {final_output_csv}")
