import pandas as pd
import random
import os 

random.seed(520)
full_label_friday_path = "../CICFlowMeter_Processed_Friday_flow_labeled/Friday_two_days_Full_Labeled.csv"
cleaned_friday_root = "../CICFlowMeter_Processed_Friday_flow_labeled_cleaned"
cleaned_friday_path = os.path.join(cleaned_friday_root, "two_fridays_labeled_cleaned")
os.makedirs(cleaned_friday_root, exist_ok=True)

df = pd.read_csv(full_label_friday_path)

remove_features = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Timestamp', 'Pkt Len Var']

df = df.drop(columns=remove_features)

benign_count = (df['Label'] == 'Benign').sum()
attack_count = (df['Label'] != 'Benign').sum()

print("===================")
print(f"There are {benign_count} Benign flow")
print(f"There are {attack_count} Malicious flow")
print("===================")

print("Undersampling Benign flows to be ratio 2:1 to Malicious Flow")

