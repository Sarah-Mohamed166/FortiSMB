// lib/core/constants/api_constants.dart
// SOURCE OF TRUTH: main.py → uvicorn endpoint.main:app --reload → port 8000
// sysmon_listener.py → writes to ClickHouse → fortismb.sysmon_predictions

class ApiConstants {
  ApiConstants._();

  // ── Switch this based on your environment ───────────────────
  // Android Emulator  : http://10.0.2.2:8000
  // Desktop / Web     : http://127.0.0.1:8000
  // Real Device       : http://192.168.x.x:8000  (your local IP)
  static const String baseUrl = 'http://10.0.2.2:8000';

  // ── Endpoints (from main.py) ─────────────────────────────────
  // GET  /          → health check
  // POST /predict   → main prediction endpoint
  static const String health  = '/';
  static const String predict = '/predict';
  static const String signup = '/auth/signup';
  static const String login = '/auth/login';

  // ── ClickHouse (from docker-compose.yml) ────────────────────
  // ClickHouse HTTP port 8123
  // DB: fortismb  User: default  Password: FortiSMB
  // Table: fortismb.sysmon_predictions
  // Columns: ai_query, action, role, file_op, is_usb, hour,
  //          off_hours, final_risk, system_action, explanation
  static const String clickhouseBase = 'http://10.0.2.2:8123';
  static const String clickhouseUser = 'default';
  static const String clickhousePass = 'FortiSMB';
  static const String clickhouseDb   = 'fortismb';
  static const String sysmonTable    = 'fortismb.sysmon_predictions';

  // ── Timeouts ────────────────────────────────────────────────
  static const Duration connectTimeout = Duration(seconds: 10);
  static const Duration receiveTimeout = Duration(seconds: 30);

  // ── Polling interval for Sysmon real-time refresh ───────────
  static const Duration pollInterval = Duration(seconds: 5);
}

// ── FortiSMB Roles (from main.py QueryRequest Literal) ─────────
class FortiSMBRoles {
  static const String adminEmployee  = 'Administrative Employee';
  static const String adminManager   = 'Administrative Manager';
  static const String contractor     = 'Contractor';
  static const String sysAdmin       = 'System Administrator';
  static const String executive      = 'Executive';

  static const List<String> all = [
    adminEmployee,
    adminManager,
    contractor,
    sysAdmin,
    executive,
  ];
}

// ── Actions (from main.py QueryRequest Literal) ─────────────────
class FortiSMBActions {
  static const String logon  = 'logon';
  static const String file   = 'file';
  static const String device = 'device';
}
