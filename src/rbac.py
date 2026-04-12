# src/rbac.py
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Set


def _lower(s: Optional[str]) -> str:
    return (s or "").lower()


def _contains_any(text: str, keywords: Set[str]) -> bool:
    t = text.lower()
    return any(k in t for k in keywords)


def _parse_dt(ts: str) -> Optional[datetime]:
    for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except Exception:
            pass
    return None


def _is_off_hours(dt: datetime, start_hour: int = 8, end_hour: int = 18) -> bool:
    return not (start_hour <= dt.hour < end_hour)


# Keyword proxies for folder sensitivity
CONF_EXEC = {"confidential", "executive", "board"}
HR_FIN = {"hr", "payroll", "salary", "finance", "accounting", "billing"}
SYS_TECH = {"sysadmin", "admin", "system32", "logs", "audit", "config", "registry"}
SENSITIVE = CONF_EXEC | HR_FIN


@dataclass
class Event:
    user: str
    role: str
    action: str
    timestamp: str
    file_path: str = ""
    file_op: str = ""
    is_usb: bool = False


def rbac_violations(event: Event, *, downloads_in_window: int = 0, download_threshold: int = 200) -> List[str]:
    """
    Returns violation codes based on the original rules.
    Only role names and corresponding violation code names were updated
    to reflect administrative role taxonomy.
    """
    role = event.role
    action = event.action.lower()
    path = _lower(event.file_path)
    op = _lower(event.file_op)
    dt = _parse_dt(event.timestamp)

    v: List[str] = []

    # ADMINISTRATIVE EMPLOYEE
    if role == "Administrative Employee":
        if action == "device" or (action == "file" and event.is_usb):
            v.append("ADMIN_EMP_USB_NOT_ALLOWED")
        if action == "file" and _contains_any(path, CONF_EXEC):
            v.append("ADMIN_EMP_CONF_EXEC_ACCESS_NOT_ALLOWED")
        if action == "logon" and dt and _is_off_hours(dt):
            v.append("ADMIN_EMP_OFF_HOURS_LOGON_NOT_ALLOWED")
        if downloads_in_window >= download_threshold:
            v.append("ADMIN_EMP_LARGE_DOWNLOAD_NOT_ALLOWED")

    # ADMINISTRATIVE MANAGER
    elif role == "Administrative Manager":
        if action == "file" and (_contains_any(path, HR_FIN) or _contains_any(path, SYS_TECH)):
            v.append("ADMIN_MGR_HR_FIN_SYS_NOT_ALLOWED")
        if downloads_in_window >= download_threshold:
            v.append("ADMIN_MGR_HIGH_VOLUME_DOWNLOAD_NOT_ALLOWED")
        if action == "device" or (action == "file" and event.is_usb):
            v.append("ADMIN_MGR_UNAUTHORIZED_DEVICE_NOT_ALLOWED")
        if action == "file" and ("write" in op or "delete" in op) and _contains_any(path, {"config", "registry"}):
            v.append("ADMIN_MGR_SYSTEM_CONFIG_EDIT_NOT_ALLOWED")

    # CONTRACTOR
    elif role == "Contractor":
        in_scope = _contains_any(path, {"project", "docs", "documentation"})
        if action == "file" and not in_scope:
            v.append("CTR_OUTSIDE_SCOPE_NOT_ALLOWED")
        if action == "file" and _contains_any(path, SENSITIVE):
            v.append("CTR_SENSITIVE_DATA_NOT_ALLOWED")
        if action == "file" and ("copy" in op or "write" in op):
            v.append("CTR_COPY_DOWNLOAD_NOT_ALLOWED")

    # SYSTEM ADMINISTRATOR
    elif role == "System Administrator":
        if action == "file" and _contains_any(path, SENSITIVE):
            v.append("SYS_SENSITIVE_ACCESS_NOT_ALLOWED")
        if action == "file" and ("copy" in op or "read" in op) and _contains_any(path, {"users", "home", "profiles"}):
            v.append("SYS_USER_DATA_COPY_NOT_ALLOWED")

    # EXECUTIVE
    elif role == "Executive":
        if action == "file" and _contains_any(path, SYS_TECH):
            v.append("EXEC_TECH_LOGS_ADMIN_TOOLS_NOT_ALLOWED")
        if action == "file" and ("write" in op or "delete" in op) and _contains_any(path, {"config", "registry"}):
            v.append("EXEC_CONFIG_EDIT_NOT_ALLOWED")
        if downloads_in_window >= download_threshold:
            v.append("EXEC_BULK_DOWNLOAD_NOT_ALLOWED")

    else:
        v.append("UNKNOWN_ROLE")

    return v


def is_allowed(event: Event, *, downloads_in_window: int = 0, download_threshold: int = 200) -> bool:
    return len(
        rbac_violations(
            event,
            downloads_in_window=downloads_in_window,
            download_threshold=download_threshold
        )
    ) == 0