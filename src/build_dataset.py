"""
Build a unified event table from CERT-style logs:
- users.csv (role lookup)
- logon.csv -> action=logon
- device.csv -> action=device
- file.csv  -> action=file

Adds:
- source_role
- fortismb_role
- rbac_allowed (True/False)
- rbac_violations (list as string)
- violation_status
- hour
- off_hours
- is_usb
- file_op

Writes:
- data/processed_events.csv
- data/rbac_allowed_counts.csv
- data/role_mapping_summary.csv
- data/role_hierarchy_mapping.png
- data/top10_source_roles_violation_bar.png
- data/mapped_roles_violation_bar.png
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Tuple

import matplotlib.pyplot as plt
import pandas as pd

from mapping import map_role_to_fortismb
from rbac import Event, rbac_violations


plt.rcParams.update({
    "font.size": 16,
    "axes.titlesize": 22,
    "axes.labelsize": 18,
    "xtick.labelsize": 16,
    "ytick.labelsize": 16,
    "legend.fontsize": 16,
    "figure.titlesize": 24
})


SRC_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SRC_DIR.parent
BASE = PROJECT_ROOT / "data" / "raw"
OUT_DIR = PROJECT_ROOT / "data"


def ensure_output_dir() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)


def safe_remove(path: Path) -> None:
    if path.exists():
        try:
            path.unlink()
        except PermissionError:
            raise PermissionError(
                f"Permission denied: '{path}'. Close the file in Excel, VS Code, "
                f"or any other app, then run the script again."
            )


def safe_to_csv(df: pd.DataFrame, path: Path) -> None:
    ensure_output_dir()
    safe_remove(path)
    df.to_csv(path, index=False)


def build_role_tables(users_path: Path) -> Tuple[Dict[str, str], Dict[str, str], pd.DataFrame]:
    users = pd.read_csv(users_path)
    users["user_id"] = users["user_id"].astype(str)
    users["source_role"] = users["role"].astype(str)
    users["fortismb_role"] = users["source_role"].apply(map_role_to_fortismb)

    source_role_lookup = dict(zip(users["user_id"], users["source_role"]))
    mapped_role_lookup = dict(zip(users["user_id"], users["fortismb_role"]))

    mapping_summary = (
        users.groupby(["source_role", "fortismb_role"], dropna=False)
        .size()
        .reset_index(name="user_count")
        .sort_values(
            ["fortismb_role", "user_count", "source_role"],
            ascending=[True, False, True],
        )
    )

    return source_role_lookup, mapped_role_lookup, mapping_summary


def build_logon_events(logon_path: Path, source_role_lookup: dict, mapped_role_lookup: dict) -> pd.DataFrame:
    df = pd.read_csv(logon_path)
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
    out["source_role"] = out["user_id"].map(source_role_lookup).fillna("Unknown")
    out["fortismb_role"] = out["user_id"].map(mapped_role_lookup).fillna("Administrative Employee")
    return out


def build_device_events(device_path: Path, source_role_lookup: dict, mapped_role_lookup: dict) -> pd.DataFrame:
    df = pd.read_csv(device_path)
    out = pd.DataFrame({
        "id": df["id"],
        "timestamp": df["date"].astype(str),
        "user_id": df["user"].astype(str),
        "pc": df["pc"].astype(str),
        "action": "device",
        "file_path": df["file_tree"].astype(str) if "file_tree" in df.columns else "",
        "file_op": "",
        "is_usb": True,
        "raw_activity": df["activity"].astype(str),
    })
    out["source_role"] = out["user_id"].map(source_role_lookup).fillna("Unknown")
    out["fortismb_role"] = out["user_id"].map(mapped_role_lookup).fillna("Administrative Employee")
    return out


def build_file_events(file_path: Path, source_role_lookup: dict, mapped_role_lookup: dict) -> pd.DataFrame:
    df = pd.read_csv(file_path)
    out = pd.DataFrame({
        "id": df["id"],
        "timestamp": df["date"].astype(str),
        "user_id": df["user"].astype(str),
        "pc": df["pc"].astype(str),
        "action": "file",
        "file_path": df["filename"].astype(str),
        "file_op": df["activity"].astype(str),
        "is_usb": (
            (df.get("to_removable_media", False) == True)
            | (df.get("from_removable_media", False) == True)
        ),
        "raw_activity": df["activity"].astype(str),
    })
    out["source_role"] = out["user_id"].map(source_role_lookup).fillna("Unknown")
    out["fortismb_role"] = out["user_id"].map(mapped_role_lookup).fillna("Administrative Employee")
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
        violations = rbac_violations(e)
        violations_list.append("|".join(violations) if violations else "")
        allowed_list.append(len(violations) == 0)

    events = events.copy()
    events["rbac_violations"] = violations_list
    events["rbac_allowed"] = allowed_list
    events["violation_status"] = events["rbac_allowed"].map(
        {True: "No Violation", False: "Violation"}
    )

    dt = pd.to_datetime(events["timestamp"], errors="coerce")
    events["hour"] = dt.dt.hour
    events["off_hours"] = events["hour"].isna() | ~events["hour"].between(8, 17)

    return events


def save_rbac_allowed_counts(events: pd.DataFrame, out_path: Path) -> pd.DataFrame:
    counts = (
        events["rbac_allowed"]
        .fillna(False)
        .map({True: "Allowed", False: "Not Allowed"})
        .value_counts()
        .rename_axis("rbac_allowed_label")
        .reset_index(name="event_count")
    )
    safe_to_csv(counts, out_path)
    return counts


def save_role_hierarchy_graph(mapping_summary: pd.DataFrame, out_path: Path) -> None:
    if mapping_summary.empty:
        return

    source_totals = (
        mapping_summary.groupby("source_role", as_index=False)["user_count"]
        .sum()
        .sort_values(["user_count", "source_role"], ascending=[False, True])
    )
    target_totals = (
        mapping_summary.groupby("fortismb_role", as_index=False)["user_count"]
        .sum()
        .sort_values(["user_count", "fortismb_role"], ascending=[False, True])
    )

    fig_height = max(7, 0.5 * max(len(source_totals), len(target_totals)))
    fig, ax = plt.subplots(figsize=(16, fig_height))
    ax.axis("off")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_title(
        "Administrative Role Hierarchy Mapping: Original Role → Standardized RBAC Role",
        fontsize=22,
        fontweight="bold",
        pad=20
    )

    left_x = 0.12
    right_x = 0.88
    node_half_height = 0.02

    def positions(items: pd.DataFrame) -> dict:
        count = len(items)
        if count == 1:
            ys = [0.5]
        else:
            top, bottom = 0.92, 0.08
            step = (top - bottom) / (count - 1)
            ys = [top - i * step for i in range(count)]
        return {name: y for name, y in zip(items.iloc[:, 0], ys)}

    left_pos = positions(source_totals[["source_role"]])
    right_pos = positions(target_totals[["fortismb_role"]])

    max_edge = max(mapping_summary["user_count"].max(), 1)
    for row in mapping_summary.itertuples(index=False):
        x1, y1 = left_x + 0.02, left_pos[row.source_role]
        x2, y2 = right_x - 0.02, right_pos[row.fortismb_role]
        linewidth = 1.0 + 8.0 * (row.user_count / max_edge)
        ax.plot([x1, x2], [y1, y2], linewidth=linewidth, alpha=0.35)

        mid_x, mid_y = (x1 + x2) / 2, (y1 + y2) / 2
        ax.text(
            mid_x,
            mid_y,
            str(row.user_count),
            fontsize=10,
            ha="center",
            va="center",
            bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.7),
        )

    for row in source_totals.itertuples(index=False):
        y = left_pos[row.source_role]
        ax.add_patch(
            plt.Rectangle(
                (left_x - 0.06, y - node_half_height),
                0.12,
                2 * node_half_height,
                fill=False
            )
        )
        ax.text(
            left_x,
            y,
            f"{row.source_role}\n({row.user_count})",
            ha="center",
            va="center",
            fontsize=11,
            fontweight="bold"
        )

    for row in target_totals.itertuples(index=False):
        y = right_pos[row.fortismb_role]
        ax.add_patch(
            plt.Rectangle(
                (right_x - 0.075, y - node_half_height),
                0.15,
                2 * node_half_height,
                fill=False
            )
        )
        ax.text(
            right_x,
            y,
            f"{row.fortismb_role}\n({row.user_count})",
            ha="center",
            va="center",
            fontsize=11,
            fontweight="bold"
        )

    ensure_output_dir()
    safe_remove(out_path)
    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def save_top10_source_roles_violation_bar(events: pd.DataFrame, out_path: Path) -> pd.DataFrame:
    top_roles = events["source_role"].value_counts().head(10).index.tolist()

    summary = (
        events[events["source_role"].isin(top_roles)]
        .groupby(["source_role", "violation_status"])
        .size()
        .unstack(fill_value=0)
    )

    for col in ["Violation", "No Violation"]:
        if col not in summary.columns:
            summary[col] = 0

    summary = summary[["Violation", "No Violation"]]
    summary["total"] = summary.sum(axis=1)
    summary = summary.sort_values("total", ascending=False).drop(columns="total")

    fig, ax = plt.subplots(figsize=(14, 8))
    summary.plot(kind="bar", ax=ax)
    ax.set_title(
        "Top 10 Original Roles: Violation vs No Violation",
        fontsize=22,
        fontweight="bold"
    )
    ax.set_xlabel("Original Role", fontsize=18, fontweight="bold")
    ax.set_ylabel("Number of Events", fontsize=18, fontweight="bold")
    ax.tick_params(axis="x", rotation=45)
    ax.legend(title="Status", title_fontsize=16, fontsize=14)
    plt.tight_layout()

    ensure_output_dir()
    safe_remove(out_path)
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)

    return summary.reset_index()


def save_mapped_roles_violation_bar(events: pd.DataFrame, out_path: Path) -> pd.DataFrame:
    summary = (
        events.groupby(["fortismb_role", "violation_status"])
        .size()
        .unstack(fill_value=0)
    )

    for col in ["Violation", "No Violation"]:
        if col not in summary.columns:
            summary[col] = 0

    summary = summary[["Violation", "No Violation"]]
    summary["total"] = summary.sum(axis=1)
    summary = summary.sort_values("total", ascending=False).drop(columns="total")

    fig, ax = plt.subplots(figsize=(14, 8))
    summary.plot(kind="bar", ax=ax)
    ax.set_title(
        "Administrative RBAC Roles: Violation vs No Violation",
        fontsize=22,
        fontweight="bold"
    )
    ax.set_xlabel("Mapped Role", fontsize=18, fontweight="bold")
    ax.set_ylabel("Number of Events", fontsize=18, fontweight="bold")
    ax.tick_params(axis="x", rotation=25)
    ax.legend(title="Status", title_fontsize=16, fontsize=14)
    plt.tight_layout()

    ensure_output_dir()
    safe_remove(out_path)
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)

    return summary.reset_index()


def main():
    ensure_output_dir()

    users_path = BASE / "users.csv"
    logon_path = BASE / "logon.csv"
    device_path = BASE / "device.csv"
    file_path = BASE / "file.csv"

    for path in [users_path, logon_path, device_path, file_path]:
        if not path.exists():
            raise FileNotFoundError(f"Missing input file: {path}")

    source_role_lookup, mapped_role_lookup, mapping_summary = build_role_tables(users_path)

    logon = build_logon_events(logon_path, source_role_lookup, mapped_role_lookup)
    device = build_device_events(device_path, source_role_lookup, mapped_role_lookup)
    file_df = build_file_events(file_path, source_role_lookup, mapped_role_lookup)

    events = pd.concat([logon, device, file_df], ignore_index=True)

    events["_ts"] = pd.to_datetime(events["timestamp"], errors="coerce")
    events = events.sort_values(by=["_ts", "user_id"], kind="mergesort").drop(columns=["_ts"])

    events = apply_rbac(events)

    processed_out = OUT_DIR / "processed_events.csv"
    counts_out = OUT_DIR / "rbac_allowed_counts.csv"
    mapping_out = OUT_DIR / "role_mapping_summary.csv"
    hierarchy_graph_out = OUT_DIR / "role_hierarchy_mapping.png"
    top10_bar_out = OUT_DIR / "top10_source_roles_violation_bar.png"
    mapped_bar_out = OUT_DIR / "mapped_roles_violation_bar.png"

    safe_to_csv(events, processed_out)
    counts = save_rbac_allowed_counts(events, counts_out)
    safe_to_csv(mapping_summary, mapping_out)
    save_role_hierarchy_graph(mapping_summary, hierarchy_graph_out)

    top10_summary = save_top10_source_roles_violation_bar(events, top10_bar_out)
    mapped_summary = save_mapped_roles_violation_bar(events, mapped_bar_out)

    print(f"Saved unified events to: {processed_out}")
    print(f"Saved RBAC label counts to: {counts_out}")
    print(f"Saved role mapping summary to: {mapping_out}")
    print(f"Saved role hierarchy graph to: {hierarchy_graph_out}")
    print(f"Saved top 10 source roles violation bar chart to: {top10_bar_out}")
    print(f"Saved mapped roles violation bar chart to: {mapped_bar_out}")

    print("\nPreview:")
    print(events.head(20).to_string(index=False))

    print("\nRBAC allowed counts:")
    print(counts.to_string(index=False))

    print("\nTop 10 original roles summary:")
    print(top10_summary.to_string(index=False))

    print("\nMapped roles summary:")
    print(mapped_summary.to_string(index=False))


if __name__ == "__main__":
    main()