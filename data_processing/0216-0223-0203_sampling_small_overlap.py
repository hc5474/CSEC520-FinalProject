import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns

SEED = 520
np.random.seed(SEED)

# Paths
train_val_path = "./CICFlowmeter_Processed_flow_labeled/0216-0223.csv"
test_path = "./CICFlowmeter_Processed_flow_labeled/0203.csv"
cleaned_root = "./processed_small_dataset"
os.makedirs(cleaned_root, exist_ok=True)

remove_features = [
    "Flow ID", "Src IP", "Dst IP", "Timestamp", "RST Flag Cnt", "Src Port", "Dst Port"
]

def preprocess_df(df, drop_cols, label_col="Label"):
    df = df.drop(columns=drop_cols, errors="ignore").drop_duplicates()
    df[label_col] = df[label_col].astype(str).str.replace(" ", "_")
    return df

# Load and preprocess
print("Loading and preprocessing...")
df_train_val = pd.read_csv(train_val_path)
df_train_val = preprocess_df(df_train_val, remove_features)

df_test_full = pd.read_csv(test_path)
df_test_full = preprocess_df(df_test_full, remove_features)

# Sample benign flows
benign_tv = df_train_val[df_train_val["Label"] == "Benign"]
malicious_tv = df_train_val[df_train_val["Label"] != "Benign"]

benign_0216 = benign_tv.sample(n=20000, random_state=SEED)
benign_0223 = benign_tv.drop(index=benign_0216.index).sample(n=20000, random_state=SEED+1)

malicious_tv_upsampled = malicious_tv.sample(n=20000, replace=True, random_state=SEED)

# Sample benign from 0203 (split between training and test)
benign_0203 = df_test_full[df_test_full["Label"] == "Benign"]
benign_0203_train = benign_0203.sample(n=20000, random_state=SEED)
benign_0203_test = benign_0203.drop(index=benign_0203_train.index).sample(n=2000, random_state=SEED+1)

# Sample malicious from 0203
malicious_0203_test = df_test_full[df_test_full["Label"] != "Benign"].sample(n=2000, random_state=SEED)

# Combine final sets
df_tv_final = pd.concat([benign_0216, benign_0223, benign_0203_train, malicious_tv_upsampled], ignore_index=True)
df_test_final = pd.concat([benign_0203_test, malicious_0203_test], ignore_index=True)

# Log transform
def log_transform_skewed(df, exclude=["Label"], threshold=1.0):
    numeric_cols = df.select_dtypes(include=[np.number]).columns.difference(exclude)
    skewed = df[numeric_cols].skew().abs()
    skewed_cols = skewed[skewed > threshold].index.tolist()
    print(f"Applying log1p to skewed features: {skewed_cols}")
    df[skewed_cols] = np.log1p(df[skewed_cols])
    return df, skewed_cols

df_tv_final, log_features = log_transform_skewed(df_tv_final)

# Drop correlated
def drop_highly_correlated(df, threshold=0.95):
    corr = df.select_dtypes(include=[np.number]).corr().abs()
    upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
    to_drop = [col for col in upper.columns if any(upper[col] > threshold)]
    print(f"Dropping correlated features: {to_drop}")
    df = df.drop(columns=to_drop)
    return df, to_drop

df_tv_features = df_tv_final.drop(columns=["Label"])
df_tv_features, dropped_features = drop_highly_correlated(df_tv_features)
df_tv_final = pd.concat([df_tv_features, df_tv_final["Label"]], axis=1)

# Apply transforms to test set
df_test_final[log_features] = np.log1p(df_test_final[log_features])
df_test_final = df_test_final.drop(columns=dropped_features, errors="ignore")

# Train/val split
train, val = train_test_split(df_tv_final, test_size=0.2, random_state=SEED, shuffle=True)

# X_test / y_test split
X_test = df_test_final.drop(columns=["Label"])
y_test = df_test_final["Label"]

# Save CSVs
print("Saving preprocessed datasets...")
train.to_csv(f"{cleaned_root}/X_train.csv", index=False)
val.to_csv(f"{cleaned_root}/X_val.csv", index=False)
X_test.to_csv(f"{cleaned_root}/X_test.csv", index=False)
y_test.to_csv(f"{cleaned_root}/y_test.csv", index=False)
print("Saved all processed files.")

# Dataset summary
print("===================")
print("Final Dataset Summary:")
print(f"Train set size:         {len(train)}")
print(f"  ├─ Benign:            {(train['Label'] == 'Benign').sum()}")
print(f"  └─ Malicious:         {(train['Label'] != 'Benign').sum()}")

print(f"Validation set size:    {len(val)}")
print(f"  ├─ Benign:            {(val['Label'] == 'Benign').sum()}")
print(f"  └─ Malicious:         {(val['Label'] != 'Benign').sum()}")

print(f"Test set size:          {len(df_test_final)}")
print(f"  ├─ Benign:            {(df_test_final['Label'] == 'Benign').sum()}")
print(f"  └─ Malicious:         {(df_test_final['Label'] != 'Benign').sum()}")
print("===================")

# Optional: Skew plot
top_skew = df_tv_final.drop(columns=['Label']).skew().sort_values(ascending=False).head(20)
plt.figure(figsize=(10,5))
top_skew.plot(kind='bar', color='orange')
plt.title("Top Skewed Features (Train/Val)")
plt.ylabel("Skewness")
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.show()

# Optional: Correlation heatmap
plt.figure(figsize=(12,10))
corr_matrix = df_tv_final.drop(columns=['Label']).corr()
sns.heatmap(corr_matrix, cmap="coolwarm", linewidths=0.5)
plt.title("Correlation Heatmap (Train/Val)")
plt.show()
