import os
import pandas as pd

def count_rows(file_path):
    if not os.path.exists(file_path):
        print(f"[WARNING] File not found: {file_path}")
        return 0

    try:
        count = 0
        for chunk in pd.read_csv(file_path, chunksize=100000):
            count += len(chunk)
        return count
    except Exception as e:
        print(f"[ERROR] Failed reading {file_path}: {e}")
        return 0


files = {
    "Users": "data/raw/users.csv",
    "Logon": "data/raw/logon.csv",
    "Device": "data/raw/device.csv",
    "File": "data/raw/file.csv",
    "Processed Events": "data/processed_events.csv",
    "Final Stratified": "data/fortismb_final_stratified_data.csv",
    "XAI Explanations": "data/xai_explanations.csv"
}

print("\n===== DATASET RECORD COUNTS =====\n")

for name, path in files.items():
    count = count_rows(path)
    print(f"{name}: {count:,} records")

print("\n=================================\n")