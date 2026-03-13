# src/read_and_apply_rbac_demo.py
import pandas as pd
from mapping import map_role_to_fortismb
from rbac import Event, rbac_violations

BASE = "data/raw"  # change to data/archive if needed

# Read users and build role lookup
users = pd.read_csv(f"{BASE}/users.csv")
role_col = "role"
user_col = "user_id"  # your users.csv has user_id

users["fortismb_role"] = users[role_col].apply(map_role_to_fortismb)
role_lookup = dict(zip(users[user_col].astype(str), users["fortismb_role"]))

# Read small samples (fast)
logon = pd.read_csv(f"{BASE}/logon.csv", nrows=5000)
device = pd.read_csv(f"{BASE}/device.csv", nrows=5000)
file_df = pd.read_csv(f"{BASE}/file.csv", nrows=5000)

print("logon columns:", list(logon.columns))
print("device columns:", list(device.columns))
print("file columns:", list(file_df.columns))

# IMPORTANT:
# You must set these column names based on what prints above.
# Common names in CERT versions: user, date, pc, activity, filename
def pick(df, candidates):
    for c in candidates:
        if c in df.columns:
            return c
    return None

logon_user = pick(logon, ["user", "user_id", "User"])
logon_time = pick(logon, ["date", "timestamp", "time"])
device_user = pick(device, ["user", "user_id", "User"])
device_time = pick(device, ["date", "timestamp", "time"])
file_user = pick(file_df, ["user", "user_id", "User"])
file_time = pick(file_df, ["date", "timestamp", "time"])
file_path = pick(file_df, ["file", "filename", "path", "file_path"])
file_op = pick(file_df, ["activity", "action", "operation", "op"])

missing = {
    "logon_user": logon_user, "logon_time": logon_time,
    "device_user": device_user, "device_time": device_time,
    "file_user": file_user, "file_time": file_time,
    "file_path": file_path, "file_op": file_op
}
bad = [k for k,v in missing.items() if v is None]
if bad:
    raise SystemExit(f"Missing columns: {bad}. Edit candidates in pick() based on printed columns.")

events = []

# Build events
for _, r in logon.iterrows():
    uid = str(r[logon_user])
    events.append(Event(
        user=uid,
        role=role_lookup.get(uid, "Employee"),
        action="logon",
        timestamp=str(r[logon_time])
    ))

for _, r in device.iterrows():
    uid = str(r[device_user])
    events.append(Event(
        user=uid,
        role=role_lookup.get(uid, "Employee"),
        action="device",
        timestamp=str(r[device_time])
    ))

for _, r in file_df.iterrows():
    uid = str(r[file_user])
    events.append(Event(
        user=uid,
        role=role_lookup.get(uid, "Employee"),
        action="file",
        timestamp=str(r[file_time]),
        file_path=str(r[file_path]),
        file_op=str(r[file_op]),
        is_usb=False  # later you can infer USB
    ))

# Print RBAC violations for first 100 events
viol_count = 0
for e in events[:100]:
    v = rbac_violations(e)
    if v:
        viol_count += 1
        print(f"[VIOLATION] user={e.user} role={e.role} action={e.action} time={e.timestamp} -> {v}")

print(f"\nChecked {min(100, len(events))} events. Violations found: {viol_count}")
