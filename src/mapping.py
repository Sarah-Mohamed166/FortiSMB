# src/mapping.py
# Map ALL dataset roles -> FortiSMB RBAC roles:
# Employee, Manager, Contractor, System Administrator, Executive

from __future__ import annotations

def _norm(s: str) -> str:
    """Normalize: lowercase, remove spaces/underscores/hyphens."""
    s = str(s).strip().lower()
    for ch in [" ", "_", "-"]:
        s = s.replace(ch, "")
    return s

# 1) Hard overrides (exact roles you KNOW)
# Put exact dataset role strings here (as seen in users.csv).
OVERRIDES = {
    "productionlineworker": "Employee",
    "technician": "Contractor",
    "salesman": "Executive",
    "itadmin": "System Administrator",
}

# 2) Keyword buckets (rule-based)
EXEC_KEYWORDS = {
    "chief", "ceo", "cfo", "coo", "cto",
    "president", "vicepresident", "vp",
    "executive", "director", "board",
}
MGR_KEYWORDS = {
    "manager", "supervisor", "lead", "head",
    "projectmanager", "teamlead", "foreman",
}
SYSADMIN_KEYWORDS = {
    "it", "sysadmin", "systemadministrator", "administrator",
    "security", "securityguard", "network", "devops",
    "webdeveloper", "developer", "programmer",
    "computerscientist", "softwareengineer", "softwaredeveloper",
    "testengineer", "qualityengineer", "softwarequalityengineer",
}
CONTRACTOR_KEYWORDS = {
    "contractor", "intern", "temp", "temporary", "consultant",
    "fieldserviceengineer", "technicalwriter",
}

# 3) Default: Employee (safe baseline)
DEFAULT_ROLE = "Employee"

def map_role_to_fortismb(dataset_role: str) -> str:
    r = _norm(dataset_role)

    # Overrides first
    if r in OVERRIDES:
        return OVERRIDES[r]

    # Executive
    if any(k in r for k in EXEC_KEYWORDS):
        return "Executive"

    # Manager
    if any(k in r for k in MGR_KEYWORDS):
        return "Manager"

    # System Administrator
    if any(k in r for k in SYSADMIN_KEYWORDS):
        return "System Administrator"

    # Contractor
    if any(k in r for k in CONTRACTOR_KEYWORDS):
        return "Contractor"

    # Otherwise: Employee
    return DEFAULT_ROLE

