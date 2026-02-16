# src/check_users.py
import pandas as pd
from mapping import map_role_to_fortismb

USERS_PATH = "data/raw/users.csv"  # if your csvs are in data/archive/, change path

users = pd.read_csv(USERS_PATH)

print("users.csv columns:", list(users.columns))

# Your users.csv has column name "role" (from your output)
role_col = "role"
if role_col not in users.columns:
    raise SystemExit(f"Can't find '{role_col}' column. Found: {list(users.columns)}")

users["fortismb_role"] = users[role_col].apply(map_role_to_fortismb)

print("\nUnique role mapping (first 50):")
print(users[[role_col, "fortismb_role"]].drop_duplicates().head(50).to_string(index=False))

print("\nCounts:")
print(users["fortismb_role"].value_counts().to_string())

# Save mapping table for your report/documentation
mapping_table = users[[role_col, "fortismb_role"]].drop_duplicates().sort_values(by=[role_col])
mapping_table.to_csv("data/role_mapping_table.csv", index=False)
print("\nSaved mapping table to: data/role_mapping_table.csv")
