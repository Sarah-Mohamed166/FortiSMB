// lib/data/models/sysmon_log.dart
// SOURCE: sysmon_listener.py → client.insert("fortismb.sysmon_predictions", ...)
//
// ClickHouse table columns (in order):
//   ai_query, action, role, file_op, is_usb, hour,
//   off_hours, final_risk, system_action, explanation
//
// Also from sysmon_listener.py:
//   event_id mapping:
//     EventID 1  → action = "device"
//     EventID 11 → action = "file"
//     EventID 3  → action = "logon"
//     other      → action = "file"

import 'package:intl/intl.dart';

class SysmonLog {
  final String aiQuery;       // "Sysmon Event ID {event_id}"
  final String action;        // "device" | "file" | "logon"
  final String role;          // FortiSMB role
  final String fileOp;        // e.g. "copy"
  final bool isUsb;
  final double hour;
  final bool offHours;
  final String finalRisk;     // "Low" | "Medium" | "High"
  final String systemAction;  // "Log & Monitor" | "Alert & Verify" | "Block & Mitigate"
  final String explanation;   // Gemini explanation
  final DateTime? timestamp;  // Added client-side if available

  const SysmonLog({
    required this.aiQuery,
    required this.action,
    required this.role,
    required this.fileOp,
    required this.isUsb,
    required this.hour,
    required this.offHours,
    required this.finalRisk,
    required this.systemAction,
    required this.explanation,
    this.timestamp,
  });

  /// Parses a ClickHouse JSON row
  factory SysmonLog.fromClickHouseJson(Map<String, dynamic> j) => SysmonLog(
    aiQuery:      j['ai_query']?.toString()      ?? '',
    action:       j['action']?.toString()         ?? '',
    role:         j['role']?.toString()           ?? '',
    fileOp:       j['file_op']?.toString()        ?? '',
    isUsb:        _parseBool(j['is_usb']),
    hour:         _parseDouble(j['hour']),
    offHours:     _parseBool(j['off_hours']),
    finalRisk:    j['final_risk']?.toString()     ?? 'Low',
    systemAction: j['system_action']?.toString()  ?? 'Log & Monitor',
    explanation:  j['explanation']?.toString()    ?? '',
    timestamp:    j['timestamp'] != null
        ? DateTime.tryParse(j['timestamp'].toString())
        : null,
  );

  /// Creates from a /predict response + request payload (local cache)
  factory SysmonLog.fromPrediction({
    required Map<String, dynamic> payload,
    required Map<String, dynamic> result,
  }) => SysmonLog(
    aiQuery:      payload['ai_query']?.toString()      ?? '',
    action:       payload['action']?.toString()         ?? '',
    role:         payload['fortismb_role']?.toString()  ?? '',
    fileOp:       payload['file_op']?.toString()        ?? '',
    isUsb:        _parseBool(payload['is_usb']),
    hour:         _parseDouble(payload['hour']),
    offHours:     _parseBool(payload['off_hours']),
    finalRisk:    result['final_risk']?.toString()      ?? 'Low',
    systemAction: result['system_action']?.toString()   ?? 'Log & Monitor',
    explanation:  result['ai_explanation']?.toString()  ?? '',
    timestamp:    DateTime.now(),
  );

  static bool _parseBool(dynamic v) {
    if (v == null) return false;
    if (v is bool)   return v;
    if (v is int)    return v == 1;
    if (v is String) return v == '1' || v.toLowerCase() == 'true';
    return false;
  }

  static double _parseDouble(dynamic v) {
    if (v == null) return 0;
    if (v is double) return v;
    if (v is int)    return v.toDouble();
    return double.tryParse(v.toString()) ?? 0;
  }

  /// Derive Sysmon Event ID label from ai_query
  String get eventIdLabel {
    final match = RegExp(r'Event ID (\d+)').firstMatch(aiQuery);
    return match != null ? 'ID ${match.group(1)}' : 'SYSMON';
  }

  String get formattedTime {
    if (timestamp == null) return '${hour.toInt().toString().padLeft(2,'0')}:00';
    return DateFormat('HH:mm:ss').format(timestamp!);
  }

  String get formattedDate {
    if (timestamp == null) return '';
    return DateFormat('MMM dd, yyyy').format(timestamp!);
  }

  bool get isHighRisk   => finalRisk.toLowerCase() == 'high';
  bool get isMediumRisk => finalRisk.toLowerCase() == 'medium';
  bool get isAlert      => isHighRisk || isMediumRisk;
}

// ── Alert Model derived from SysmonLog ────────────────────────
class AlertModel {
  final SysmonLog log;
  final String alertId;

  AlertModel({required this.log, required this.alertId});

  String get severity    => log.finalRisk;
  String get timestamp   => log.formattedTime;
  String get role        => log.role;
  String get action      => log.action;
  String get recommendation => log.systemAction;
  String get explanation => log.explanation;
}
