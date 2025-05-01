"""
AI Usage Statement (Han Chen)
Tools Used: ChatGPT 
    - Usage: Code runtime info printing
    - Verification: Code are manually written
Prohibited Use Compliance: Confirmed

This script is for processing labled CICFlowMeter Friday dataset.
This script:
    - Loads the full labeled CSV file containing network traffic flow data.
    - Drops non-useful metadata features (e.g., IP addresses, ports, timestamps).
    - Feature Engineer
    - Balances the dataset by undersampling benign flows to a 2:1 ratio relative to malicious flows.
    - Splits the benign flows into training (70%), validation (20%), and test (10%) sets.
    - Separates features (X) and labels (y) for model training and evaluation.
    - Saves the processed datasets (X_train, X_val, X_test, y_test) as CSV files.
"""

import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns



SEED = 520

# Paths for inputs and outputs
full_label_path = ("./CICFlowMeter_Processed_flow_labeled/Friday_two_days_Full_Labeled.csv")
cleaned_root = "./processed_friday_data"
#full_label_path = ("./CICFlowMeter_Processed_flow_labeled/Thursday_220218_Labeled.csv")
#cleaned_root = "./processed_thursday_data"


os.makedirs(cleaned_root, exist_ok=True)

print("Loading Data......")
df = pd.read_csv(full_label_path)  # Load the entire dataset into a dataframe
print("Data Loaded into dataframe")

# Dropping features that won't be very helpful for training the autoencoder
remove_features = [
     "Flow ID",
     "Src IP",
     "Dst IP",
     "Timestamp",
     "RST Flag Cnt" # Dropped bc too high skewed
 ]
print(f"Dropping Features: {remove_features}")
df = df.drop(columns=remove_features, errors="ignore")
print("Non-useful features dropped")

df = df.drop_duplicates()

feature_skewness = df.drop(columns=['Label']).skew()
skew_threshold = 1.0
log_features = feature_skewness[feature_skewness.abs() > skew_threshold].index.tolist()

print("Features selected for log1p transformation:")
print(log_features)

# Apply log1p transformation
for feature in log_features:
    if feature in df.columns:
        df[feature] = np.log1p(df[feature])
benign_count = (df["Label"] == "Benign").sum()
attack_count = (df["Label"] != "Benign").sum()

print("===================")
print(f"There are {benign_count} Benign flow")
print(f"There are {attack_count} Malicious flow")
print("===================")


def drop_highly_correlated(df, threshold=0.95):
    corr_matrix = df.corr().abs()
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    to_drop = [col for col in upper.columns if any(upper[col] > threshold)]
    return df.drop(columns=to_drop), to_drop
df_features = df.drop(columns=['Label'])
df_features, dropped_features = drop_highly_correlated(df_features)

# Reattach label
df = pd.concat([df_features, df['Label']], axis=1)

print("===================")
print("Dropped redundant features due to high correlation:")
print(dropped_features)
print("===================")

print("Undersampling Benign flows to be ratio 2:1 to Malicious Flow......")
# Undersample benign flows to achieve a 2:1 Benign-to-attack ratio
benign_sample_size = attack_count * 2
df_benign = df[df["Label"] == "Benign"]
df_attack = df[df["Label"] != "Benign"]

benign_sampled = df_benign.sample(n=benign_sample_size, random_state=SEED)

df_final = pd.concat([benign_sampled, df_attack])

df_final['Label'] = df_final['Label'].astype(str).str.replace(' ', '_')


print("===================")
print(f"Sampled Benign flows")
print(f"Size of Benign Samples: {len(benign_sampled)}")
print(f"Size of Attack Data: {len(df_attack)}")
print("===================\n")

print("Splitting Data......\n")

train, testNval = train_test_split(df_final, test_size=0.3, random_state=SEED, shuffle=True)
testNval = pd.DataFrame(testNval)
train = pd.DataFrame(train)
test, val = train_test_split(testNval, test_size=0.1, random_state=SEED, shuffle=True)
test = pd.DataFrame(test)
val = pd.DataFrame(val)

total_benign_sampled = len(benign_sampled)
total_attack = len(df_attack)

print("Processing splitted Data into usable form for ML......")
X_test = test.drop(columns=["Label"])
y_test = test["Label"]


# Saving processed data into CSV files
print("Saving processed data into CSV files...")
X_train_path = f"{cleaned_root}/X_train.csv"
X_val_path = f"{cleaned_root}/X_val.csv"
X_test_path = f"{cleaned_root}/X_test.csv"
y_test_path = f"{cleaned_root}/y_test.csv"

train.to_csv(X_train_path, index=False)
val.to_csv(X_val_path, index=False)
X_test.to_csv(X_test_path, index=False)
y_test.to_csv(y_test_path, index=False)
print("===================")
print(f"X_train saved to: {X_train_path}")
print(f"X_val saved to:   {X_val_path}")
print(f"X_test saved to:  {X_test_path}")
print(f"y_test saved to:  {y_test_path}")
print("===================")

# Feature data skewness graph
top_skewness = df_final.drop(columns=['Label']).skew().sort_values(ascending=False).head(20)

plt.figure(figsize=(10,5))
top_skewness.plot(kind='bar', color='orange')
plt.title("Top 10 Most Skewed Features")
plt.ylabel("Skewness")
plt.xlabel("Feature")
plt.xticks(rotation=45, ha='right')
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()
plt.show()

# Feature correlation Heatmap graph
plt.figure(figsize=(12,10))
corr_matrix = df_final.drop(columns=['Label']).corr()
sns.heatmap(corr_matrix, cmap="coolwarm", linewidths=0.5)
plt.title("Feature Correlation Heatmap")
plt.show()