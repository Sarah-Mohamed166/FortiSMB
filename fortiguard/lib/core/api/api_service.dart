// lib/core/api/api_service.dart
// Connects to: http://127.0.0.1:8000/predict
// Payload format matches sysmon_listener.py exactly
// Response: final_risk, system_action, ai_explanation (from llm_service.py / Gemini)

import 'dart:convert';
import 'package:http/http.dart' as http;

// ─── Request Model — matches sysmon_listener.py payload ────────
class PredictRequest {
  final String aiQuery;
  final String action;       // "file" | "device" | "logon"
  final String fortismbRole; // e.g. "Administrative Employee"
  final String fileOp;       // "copy" | "read" | "write" | "delete" | ""
  final bool   isUsb;
  final double hour;
  final bool   offHours;
  final String date;         // "2026-05-14"

  const PredictRequest({
    required this.aiQuery,
    required this.action,
    required this.fortismbRole,
    required this.fileOp,
    required this.isUsb,
    required this.hour,
    required this.offHours,
    required this.date,
  });

  Map<String, dynamic> toJson() => {
    'ai_query':      aiQuery,
    'action':        action,
    'fortismb_role': fortismbRole,
    'file_op':       fileOp,
    'is_usb':        isUsb,
    'hour':          hour,
    'off_hours':     offHours,
    'date':          date,
  };
}

// ─── Response Model — from server.log: final_risk, system_action, ai_explanation
class PredictResponse {
  final String finalRisk;      // "High" | "Medium" | "Low"
  final String systemAction;   // "Block & Mitigate" | "Alert & Verify" | "Log & Monitor"
  final String aiExplanation;  // From Gemini 2.0 Flash via llm_service.py
  final bool   fromCache;      // True if offline/demo data

  const PredictResponse({
    required this.finalRisk,
    required this.systemAction,
    required this.aiExplanation,
    this.fromCache = false,
  });

  factory PredictResponse.fromJson(Map<String, dynamic> j) => PredictResponse(
    finalRisk:     j['final_risk']     as String? ?? 'Low',
    systemAction:  j['system_action']  as String? ?? 'Log & Monitor',
    aiExplanation: j['ai_explanation'] as String? ?? '',
  );

  // Offline fallback when server not running
  factory PredictResponse.offline(PredictRequest req) {
    final isHigh = req.isUsb && req.offHours;
    final isMed  = req.offHours || req.isUsb;
    final risk   = isHigh ? 'High' : isMed ? 'Medium' : 'Low';
    final action = isHigh ? 'Block & Mitigate' : isMed ? 'Alert & Verify' : 'Log & Monitor';
    return PredictResponse(
      finalRisk:     risk,
      systemAction:  action,
      aiExplanation: 'Server offline. Local risk estimate based on RBAC rules: '
          '${req.isUsb ? "USB detected. " : ""}${req.offHours ? "Off-hours access. " : ""}Role: ${req.fortismbRole}.',
      fromCache: true,
    );
  }
}

// ─── SHAP Factor — parsed from xai_explanations.py format_pairs() output
// format: "is_usb (+0.3142); off_hours (+0.2418); ..."
class ShapFactor {
  final String feature;
  final double value;

  const ShapFactor({required this.feature, required this.value});

  bool get isPositive => value > 0;
  double get pct => (value.abs() * 100).clamp(0, 100);

  // Human-readable label matching your feature names
  String get label {
    const labels = {
      'is_usb':              'Unauthorized USB Device',
      'off_hours':           'Off-Hours Access',
      'hour':                'Suspicious Hour',
      'action_file':         'File Copy Operation',
      'action_device':       'USB Device Action',
      'action_logon':        'Login Event',
      'file_op_copy':        'File Copy Flag',
      'file_op_read':        'File Read Flag',
      'file_op_write':       'File Write Flag',
      'file_op_delete':      'File Delete Flag',
    };
    // Try direct match, else prettify
    if (labels.containsKey(feature)) return labels[feature]!;
    return feature.replaceAll('_', ' ').toUpperCase();
  }
}

// Parses "is_usb (+0.3142); off_hours (+0.2418)" from xai_explanations.py format_pairs()
List<ShapFactor> parseShapText(String text) {
  if (text.trim().isEmpty) return [];
  final results = <ShapFactor>[];
  for (final part in text.split(';')) {
    final m = RegExp(r'(.+?)\s*\(([+-]?\d+\.\d+)\)').firstMatch(part.trim());
    if (m == null) continue;
    final val = double.tryParse(m.group(2)!);
    if (val != null) {
      results.add(ShapFactor(feature: m.group(1)!.trim(), value: val));
    }
  }
  return results;
}

// ─── API Service ───────────────────────────────────────────────
class ApiService {
  static const String _base = 'http://127.0.0.1:8000';
  static const Duration _timeout = Duration(seconds: 8);

  /// POST /predict — main endpoint from sysmon_listener.py
  static Future<PredictResponse> predict(PredictRequest req) async {
    try {
      final uri      = Uri.parse('$_base/predict');
      final response = await http.post(
        uri,
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(req.toJson()),
      ).timeout(_timeout);

      if (response.statusCode == 200) {
        final json = jsonDecode(response.body) as Map<String, dynamic>;
        return PredictResponse.fromJson(json);
      }
      return PredictResponse.offline(req);
    } catch (_) {
      // Server not running → graceful offline fallback
      return PredictResponse.offline(req);
    }
  }

  /// Check if server is reachable
  static Future<bool> isServerReachable() async {
    try {
      final r = await http.get(Uri.parse('$_base/docs')).timeout(const Duration(seconds: 3));
      return r.statusCode == 200;
    } catch (_) {
      return false;
    }
  }
}
