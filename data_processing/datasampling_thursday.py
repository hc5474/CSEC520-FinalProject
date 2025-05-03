"""
Copy of datasampling.py, but this is to handle another day's data which will have a different splitting strategy.
"""

import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns



SEED = 520

# Paths for inputs and outputs

full_label_path = ("./CICFlowMeter_Processed_flow_labeled/Thursday_220218_Labeled.csv")
cleaned_root = "./processed_thursday_data"
redundant_features_path = "./processed_friday_data/dropped_features.txt"


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
     "RST Flag Cnt", # Dropped bc too high skewed
     "Src Port",
     "Dst Port"
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

print("Undersampling Benign flows to be ratio 2:1 to Malicious Flow......")
# Undersample benign flows to achieve a 2:1 Benign-to-attack ratio
benign_sample_size = attack_count * 2
df_benign = df[df["Label"] == "Benign"]
df_attack = df[df["Label"] != "Benign"]

benign_sampled = df_benign.sample(n=benign_sample_size, random_state=SEED)

df_final = pd.concat([benign_sampled, df_attack])

# Load features to drop from the file
print(f"Number of features in df_final before dropping: {len(df_final.columns) - 1}")  # Exclude 'Label' column
# Print the number of features to be dropped
with open(redundant_features_path, 'r') as file:
    dropped_features = [line.strip() for line in file.readlines()]
print(f"Number of features to be dropped: {len(dropped_features)}")
# Drop the features listed in the file
df_final_features = df_final.drop(columns=['Label'])
df_final_features = df_final_features.drop(columns=dropped_features, errors='ignore')

# Reattach label
df_final = pd.concat([df_final_features, df_final['Label']], axis=1)

print("===================")
print("Dropped redundant features due to high correlation:")
print(dropped_features)
print("===================")

df_final['Label'] = df_final['Label'].astype(str).str.replace(' ', '_')


print("===================")
print(f"Sampled Benign flows")
print(f"Size of Benign Samples: {len(benign_sampled)}")
print(f"Size of Attack Data: {len(df_attack)}")
print("===================\n")

print("Splitting Data......\n")

# =================
# TO DO
# ==============
# Separating features and labels for test and validation sets
X_test = df_final.drop(columns=['Label'])
y_test = df_final['Label']

# Saving validation data into CSV files
X_val_path = f"{cleaned_root}/X_val.csv"
y_val_path = f"{cleaned_root}/y_val.csv"

X_test.to_csv(X_val_path, index=False)
y_test.to_csv(y_val_path, index=False)
print("===================")
print(f"X_val saved to:  {X_val_path}")
print(f"y_val saved to:  {y_val_path}")
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