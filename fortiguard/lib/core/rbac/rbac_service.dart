// lib/core/rbac/rbac_service.dart
// Dart port of your rbac.py and mapping.py
// These exact violation codes come from xai_explanations.py RBAC_REASON_MAP

/// The 5 FortiSMB roles from mapping.py
enum FortiSMBRole {
  administrativeEmployee,
  administrativeManager,
  contractor,
  systemAdministrator,
  executive,
  securityAnalyst, // not in dataset but used in app for SA login
}

extension FortiSMBRoleX on FortiSMBRole {
  String get apiName {
    switch (this) {
      case FortiSMBRole.administrativeEmployee: return 'Administrative Employee';
      case FortiSMBRole.administrativeManager:  return 'Administrative Manager';
      case FortiSMBRole.contractor:             return 'Contractor';
      case FortiSMBRole.systemAdministrator:    return 'System Administrator';
      case FortiSMBRole.executive:              return 'Executive';
      case FortiSMBRole.securityAnalyst:        return 'Security Analyst';
    }
  }

  String get displayName => apiName;

  /// Only Security Analyst gets full dashboard access
  bool get canAccessDashboard => this == FortiSMBRole.securityAnalyst;

  static FortiSMBRole fromString(String s) {
    switch (s.trim()) {
      case 'Administrative Employee': return FortiSMBRole.administrativeEmployee;
      case 'Administrative Manager':  return FortiSMBRole.administrativeManager;
      case 'Contractor':              return FortiSMBRole.contractor;
      case 'System Administrator':    return FortiSMBRole.systemAdministrator;
      case 'Executive':               return FortiSMBRole.executive;
      case 'Security Analyst':        return FortiSMBRole.securityAnalyst;
      default:                        return FortiSMBRole.administrativeEmployee;
    }
  }
}

// ─── Ported from mapping.py ────────────────────────────────────
/// Maps any free-text role to a FortiSMB RBAC role — mirrors map_role_to_fortismb()
FortiSMBRole mapRoleToFortiSMB(String datasetRole) {
  final r = datasetRole.trim().toLowerCase()
      .replaceAll(' ', '').replaceAll('_', '').replaceAll('-', '');

  // Hard overrides (OVERRIDES dict in mapping.py)
  const overrides = {
    'productionlineworker': FortiSMBRole.administrativeEmployee,
    'technician':           FortiSMBRole.contractor,
    'salesman':             FortiSMBRole.executive,
    'itadmin':              FortiSMBRole.systemAdministrator,
  };
  if (overrides.containsKey(r)) return overrides[r]!;

  // Executive keywords
  const execKw = {'chief','ceo','cfo','coo','cto','president','vicepresident','vp','executive','director','board'};
  if (execKw.any((k) => r.contains(k))) return FortiSMBRole.executive;

  // Manager keywords
  const mgrKw = {'manager','supervisor','lead','head','projectmanager','teamlead','foreman'};
  if (mgrKw.any((k) => r.contains(k))) return FortiSMBRole.administrativeManager;

  // SysAdmin keywords
  const sysKw = {'it','sysadmin','systemadministrator','administrator','security','network','devops','developer','programmer'};
  if (sysKw.any((k) => r.contains(k))) return FortiSMBRole.systemAdministrator;

  // Contractor keywords
  const ctrKw = {'contractor','intern','temp','temporary','consultant'};
  if (ctrKw.any((k) => r.contains(k))) return FortiSMBRole.contractor;

  return FortiSMBRole.administrativeEmployee;
}

// ─── Ported from xai_explanations.py RBAC_REASON_MAP ──────────
const Map<String, String> rbacReasonMap = {
  'ADMIN_EMP_USB_NOT_ALLOWED':
      'Administrative employee used a USB/device action that is not allowed by policy.',
  'ADMIN_EMP_CONF_EXEC_ACCESS_NOT_ALLOWED':
      'Administrative employee tried to access confidential, executive, or board-related files.',
  'ADMIN_EMP_OFF_HOURS_LOGON_NOT_ALLOWED':
      'Administrative employee logged in outside approved working hours.',
  'ADMIN_EMP_LARGE_DOWNLOAD_NOT_ALLOWED':
      'Administrative employee exceeded the allowed download threshold.',
  'ADMIN_MGR_HR_FIN_SYS_NOT_ALLOWED':
      'Administrative manager tried to access HR, finance, or system-technical files.',
  'ADMIN_MGR_HIGH_VOLUME_DOWNLOAD_NOT_ALLOWED':
      'Administrative manager exceeded the allowed download threshold.',
  'ADMIN_MGR_UNAUTHORIZED_DEVICE_NOT_ALLOWED':
      'Administrative manager used an unauthorized device or USB-related action.',
  'ADMIN_MGR_SYSTEM_CONFIG_EDIT_NOT_ALLOWED':
      'Administrative manager attempted to modify protected system configuration or registry files.',
  'CTR_OUTSIDE_SCOPE_NOT_ALLOWED':
      'Contractor accessed files outside the allowed project/documentation scope.',
  'CTR_SENSITIVE_DATA_NOT_ALLOWED':
      'Contractor accessed sensitive data that is forbidden by policy.',
  'CTR_COPY_DOWNLOAD_NOT_ALLOWED':
      'Contractor attempted to copy or write files, which is not allowed.',
  'SYS_SENSITIVE_ACCESS_NOT_ALLOWED':
      'System administrator accessed sensitive business data outside permitted scope.',
  'SYS_USER_DATA_COPY_NOT_ALLOWED':
      'System administrator copied or read user profile/home data, which is restricted.',
  'EXEC_TECH_LOGS_ADMIN_TOOLS_NOT_ALLOWED':
      'Executive accessed technical admin tools or logs that are not permitted.',
  'EXEC_CONFIG_EDIT_NOT_ALLOWED':
      'Executive attempted to modify protected configuration or registry files.',
  'EXEC_BULK_DOWNLOAD_NOT_ALLOWED':
      'Executive exceeded the allowed bulk download threshold.',
};

String violationText(String codes) {
  if (codes.trim().isEmpty) return 'No RBAC violation.';
  return codes.split('|')
      .map((c) => rbacReasonMap[c.trim()] ?? 'Unknown: ${c.trim()}')
      .join('\n• ');
}

// ─── Session Manager ───────────────────────────────────────────
class SessionManager {
  SessionManager._();
  static FortiSMBRole? currentRole;
  static String currentName  = 'Security Analyst';
  static String employeeId   = 'EMP-0082';

  static bool get isAuthorized => currentRole?.canAccessDashboard ?? false;

  static void login(FortiSMBRole role, {String name = 'Security Analyst', String empId = 'EMP-0082'}) {
    currentRole = role;
    currentName = name;
    employeeId  = empId;
  }

  static void logout() {
    currentRole = null;
    currentName = 'Security Analyst';
    employeeId  = 'EMP-0082';
  }
}
