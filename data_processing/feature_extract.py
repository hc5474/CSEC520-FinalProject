'''
AI Usage: Error catching
'''

import os
import subprocess

# Paths
project_root = r"/Users/hanchen/Desktop/Junior Spring/CSEC 520 Cyber Machine Learning/CSEC520-FinalProject"
sampled_root = os.path.join(project_root, "sampled_data")
flow_output_root = os.path.join(project_root, "flow_output")

# Command to run cicflowmeter
def run_cicflowmeter(pcap_path, output_csv):
    cmd = [
        "cicflowmeter",
        "-f", pcap_path,
        "-c", output_csv
    ]
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

days = ["Friday-02-03-2018", "Friday-16-02-2018", "Friday-23-02-2018"]

for day in days:
    pcap_dir = os.path.join(sampled_root, day)
    output_dir = os.path.join(flow_output_root, day)

    os.makedirs(output_dir, exist_ok=True)

    pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith('.pcap')]

    for fname in pcap_files:
        pcap_path = os.path.join(pcap_dir, fname)
        output_csv = os.path.join(output_dir, f"{os.path.splitext(fname)[0]}.csv") 
        
        try:
            result = run_cicflowmeter(pcap_path, output_csv)
            if result.returncode == 0:
                print(f"[+] Successfully processed: {fname}")
            else:
                print(f"[!] Error processing {fname}: {result.stderr.decode()}")
        except Exception as e:
            print(f"[!] Failed to process {fname}: {str(e)}")
