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
