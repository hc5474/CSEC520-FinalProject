'''
This script is used by Han's Desktop where he had the entire dataset stored.
The dataset was very huge (~450G) so we decided to use only a subset of all Fridays' pcap files.

This script randomly samples a specified number of PCAP files from selected days
of the CSE-CIC-IDS2018 dataset and copies into a new project directory structure.

For each listed day, it randomly selectes 50 PCAP files.
It copis the sampled PCAPs into the destination folder.
Uses a fixed random seed, 520

This script is specifically used to sample from the original dataset. 
'''

import os
import shutil
import random

project_root = r"D:\CSEC520-Project"
src_root = os.path.join(project_root, "Original Network Traffic and Log data")
dst_root = os.path.join(project_root, "CSEC520-FinalProject", "sampled_data")

days = ["Friday-02-03-2018", "Friday-16-02-2018", "Friday-23-02-2018"]
sample_size = 50
random.seed(520)

for day in days:
    src_pcap_dir = os.path.join(src_root, day, "pcap")
    dst_pcap_dir = os.path.join(dst_root, day)

    os.makedirs(dst_pcap_dir, exist_ok=True)

    pcap_files = [f for f in os.listdir(src_pcap_dir)]

    sampled = random.sample(pcap_files, sample_size)

    for fname in sampled:
        shutil.copy2(os.path.join(src_pcap_dir, fname), os.path.join(dst_pcap_dir, f"{fname}.pcap"))

    print(f"Sampled {len(sampled)} files from {day} → {dst_pcap_dir}")
