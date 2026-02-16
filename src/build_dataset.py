# src/build_dataset.py
"""
Build a unified event table from CERT-style logs:
- users.csv (role lookup)
- logon.csv -> action=logon
- device.csv -> action=device
- file.csv  -> action=file

Adds:
- fortismb_role
- rbac_allowed (True/False)
- violations (list as a string)
- simple features: hour, off_hours, is_usb, file_op
"""

import pandas as pd

from mapping import map_role_to_fortismb
from rbac import Event, rbac_violations


BASE = "data/raw"  # change to "data/archive" if needed


def build_role_lookup(users_path: str) -> dict:
    users = pd.read_csv(users_path)
    # your users.csv has user_id and role
    users["fortismb_role"] = users["role"].apply(map_role_to_fortismb)
    return dict(zip(users["user_id"].astype(str), users["fortismb_role"]))


def build_logon_events(logon_path: str, role_lookup: dict) -> pd.DataFrame:
    df = pd.read_csv(logon_path)
    # your columns: ['id','date','user','pc','activity']
    out = pd.DataFrame({
        "id": df["id"],
        "timestamp": df["date"].astype(str),
        "user_id": df["user"].astype(str),
        "pc": df["pc"].astype(str),
        "action": "logon",
        "file_path": "",
        "file_op": "",
        "is_usb": False,
        "raw_activity": df["activity"].astype(str),
    })
    out["fortismb_role"] = out["user_id"].map(role_lookup).fillna("Employee")
    return out


def build_device_events(device_path: str, role_lookup: dict) -> pd.DataFrame:
    df = pd.read_csv(device_path)
    # your columns: ['id','date','user','pc','file_tree','activity']
    out = pd.DataFrame({
        "id": df["id"],
        "timestamp": df["date"].astype(str),
        "user_id": df["user"].astype(str),
        "pc": df["pc"].astype(str),
        "action": "device",
        "file_path": df.get("file_tree", "").astype(str) if "file_tree" in df.columns else "",
        "file_op": "",
        "is_usb": True,  # device events are USB-related by nature
        "raw_activity": df["activity"].astype(str),
    })
    out["fortismb_role"] = out["user_id"].map(role_lookup).fillna("Employee")
    return out


def build_file_events(file_path: str, role_lookup: dict) -> pd.DataFrame:
    df = pd.read_csv(file_path)
    # your columns: ['id','date','user','pc','filename','activity','to_removable_media','from_removable_media','content']
    out = pd.DataFrame({
        "id": df["id"],
        "timestamp": df["date"].astype(str),
        "user_id": df["user"].astype(str),
        "pc": df["pc"].astype(str),
        "action": "file",
        "file_path": df["filename"].astype(str),
        "file_op": df["activity"].astype(str),
        "is_usb": (df.get("to_removable_media", False) == True) | (df.get("from_removable_media", False) == True),
        "raw_activity": df["activity"].astype(str),
    })
    out["fortismb_role"] = out["user_id"].map(role_lookup).fillna("Employee")
    return out


def apply_rbac(events: pd.DataFrame) -> pd.DataFrame:
    violations_list = []
    allowed_list = []

    for row in events.itertuples(index=False):
        e = Event(
            user=str(row.user_id),
            role=str(row.fortismb_role),
            action=str(row.action),
            timestamp=str(row.timestamp),
            file_path=str(row.file_path),
            file_op=str(row.file_op),
            is_usb=bool(row.is_usb),
        )
        v = rbac_violations(e)
        violations_list.append("|".join(v) if v else "")
        allowed_list.append(len(v) == 0)

    events = events.copy()
    events["rbac_violations"] = violations_list
    events["rbac_allowed"] = allowed_list

    # Simple time features
    dt = pd.to_datetime(events["timestamp"], errors="coerce")
    events["hour"] = dt.dt.hour
    events["off_hours"] = events["hour"].isna() | ~events["hour"].between(8, 17)

    return events


def main():
    role_lookup = build_role_lookup(f"{BASE}/users.csv")

    logon = build_logon_events(f"{BASE}/logon.csv", role_lookup)
    device = build_device_events(f"{BASE}/device.csv", role_lookup)
    file_df = build_file_events(f"{BASE}/file.csv", role_lookup)

    events = pd.concat([logon, device, file_df], ignore_index=True)

    # Sort by time (best-effort parsing)
    events["_ts"] = pd.to_datetime(events["timestamp"], errors="coerce")
    events = events.sort_values(by=["_ts", "user_id"], kind="mergesort").drop(columns=["_ts"])

    events = apply_rbac(events)

    out_path = "data/processed_events.csv"
    events.to_csv(out_path, index=False)
    print(f"Saved unified events to: {out_path}")
    print("\nPreview:")
    print(events.head(20).to_string(index=False))
    print("\nRBAC allowed counts:")
    print(events["rbac_allowed"].value_counts().to_string())


if __name__ == "__main__":
    main()
