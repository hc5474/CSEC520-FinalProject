import pandas as pd
import random
import os 
from sklearn.model_selection import train_test_split

SEED = 520
random.seed(SEED)

full_label_friday_path = "./CICFlowMeter_Processed_Friday_flow_labeled/Friday_two_days_Full_Labeled.csv"
cleaned_friday_root = "./processed_data"
os.makedirs(cleaned_friday_root, exist_ok=True)

print("Loading Data......")
df = pd.read_csv(full_label_friday_path)
print("Data Loaded into dataframe")
remove_features = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Timestamp', 'Pkt Len Var']

print(f"Dropping Features: {remove_features}")

df = df.drop(columns=remove_features)
print("Non-useful features dropped")

benign_count = (df['Label'] == 'Benign').sum()
attack_count = (df['Label'] != 'Benign').sum()

print("===================")
print(f"There are {benign_count} Benign flow")
print(f"There are {attack_count} Malicious flow")
print("===================")

print("Undersampling Benign flows to be ratio 2:1 to Malicious Flow......")

benign_sample_size = attack_count * 2
df_benign = df[df['Label'] == 'Benign']
df_attack = df[df['Label'] != 'Benign']

benign_sampled = df_benign.sample(n=benign_sample_size, random_state=SEED)

print("===================")
print(f"Sampled Benign flows")
print(f"Size of Benign Samples: {len(benign_sampled)}")
print(f"Size of Attack Data: {len(df_attack)}")
print("===================\n")

print("Splitting Data......\n")
# Spliting data: 70% benign → Training; 15% benign → Validation; 15% benign → Test benign + 100% Test attack
benign_train, benign_temp = train_test_split(benign_sampled, test_size=0.3, random_state=SEED, shuffle=True)
benign_train = pd.DataFrame(benign_train)
benign_temp = pd.DataFrame(benign_temp)
benign_val, benign_test = train_test_split(benign_temp, test_size=0.5, random_state=SEED, shuffle=True)
benign_val = pd.DataFrame(benign_val)
benign_test = pd.DataFrame(benign_test)
test_set = pd.concat([benign_test, df_attack], ignore_index=True)

total_benign_sampled = len(benign_sampled)
total_attack = len(df_attack)

print("===================")
print("Benign Samples Split:")
print(f"  Train      : {len(benign_train)} flows ({len(benign_train) / total_benign_sampled * 100:.2f}%)")
print(f"  Validation : {len(benign_val)} flows ({len(benign_val) / total_benign_sampled * 100:.2f}%)")
print(f"  Test       : {len(benign_test)} flows ({len(benign_test) / total_benign_sampled * 100:.2f}%)")
print("")
print(f"Malicious Samples (for Test only): {total_attack} flows")
print("")
print(f"Final Test Set (Benign + Malicious): {len(benign_test) + total_attack} flows")
print("===================")


print("Processing splitted Data into usable form for sklearn......")
X_train = benign_train.drop(columns=['Label'])
X_val = benign_val.drop(columns=['Label'])
X_test = test_set.drop(columns=['Label'])
y_test = test_set['Label']
print("======Done======\n")

print("Saving processed data into CSV files...")
X_train_path = f"{cleaned_friday_root}/X_train.csv"
X_val_path = f"{cleaned_friday_root}/X_val.csv"
X_test_path = f"{cleaned_friday_root}/X_test.csv"
y_test_path = f"{cleaned_friday_root}/y_test.csv"

X_train.to_csv(X_train_path, index=False)
X_val.to_csv(X_val_path, index=False)
X_test.to_csv(X_test_path, index=False)
y_test.to_csv(y_test_path, index=False)
print("===================")
print(f"X_train saved to: {X_train_path}")
print(f"X_val saved to:   {X_val_path}")
print(f"X_test saved to:  {X_test_path}")
print(f"y_test saved to:  {y_test_path}")
print("===================")

