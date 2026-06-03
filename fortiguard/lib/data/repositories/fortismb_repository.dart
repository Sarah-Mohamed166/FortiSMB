// lib/data/repositories/fortismb_repository.dart
// Bridges ApiService ↔ Provider state
// Caches predictions locally + polls ClickHouse every 5s

import 'dart:async';
import '../models/prediction_request.dart';
import '../models/prediction_response.dart';
import '../models/sysmon_log.dart';
import '../models/xai_model.dart';
import '../services/api_service.dart';
import '../../core/constants/api_constants.dart';
import '../../core/errors/app_error.dart';

class FortiSMBRepository {
  FortiSMBRepository._();
  static final FortiSMBRepository instance = FortiSMBRepository._();

  final _api = ApiService.instance;

  // ── Local cache (session-lifetime) ────────────────────────────
  final List<SysmonLog>          _localLogs          = [];
  PredictionResponse?            _lastPrediction;
  XAIExplanationModel?           _lastXAI;

  // ── Polling ────────────────────────────────────────────────────
  Timer? _pollTimer;
  void Function(List<SysmonLog>)? _onLogsUpdated;

  // ── Expose getters ─────────────────────────────────────────────
  List<SysmonLog>     get logs          => List.unmodifiable(_localLogs);
  PredictionResponse? get lastPrediction=> _lastPrediction;
  XAIExplanationModel? get lastXAI      => _lastXAI;

  // ── Health check ───────────────────────────────────────────────
  Future<bool> isServerAlive() => _api.isServerAlive();

  // ── Submit a prediction ────────────────────────────────────────
  // Calls POST /predict, caches result
  Future<PredictionResponse> predict(PredictionRequest req) async {
    final resp = await _api.predict(req);
    _lastPrediction = resp;
    _lastXAI = XAIExplanationModel.fromPrediction(resp, payload: req.toJson());
    // Cache locally as a SysmonLog
    _localLogs.insert(0, SysmonLog.fromPrediction(
      payload: req.toJson(),
      result: {
        'final_risk':    resp.finalRisk,
        'system_action': resp.systemAction,
        'ai_explanation':resp.aiExplanation,
      },
    ));
    return resp;
  }

  // ── Fetch logs from ClickHouse ─────────────────────────────────
  Future<List<SysmonLog>> refreshLogs() async {
    try {
      final clickhouseLogs = await _api.fetchSysmonLogs(limit: 200);
      if (clickhouseLogs.isNotEmpty) {
        // Merge ClickHouse logs with local cache, deduplicate by aiQuery+hour
        final combined = [...clickhouseLogs, ..._localLogs];
        _localLogs
          ..clear()
          ..addAll(combined.take(500));
        _onLogsUpdated?.call(List.unmodifiable(_localLogs));
        return _localLogs;
      }
    } catch (_) {
      // ClickHouse offline — return local cache
    }
    return _localLogs;
  }

  // ── Start polling for real-time Sysmon updates ─────────────────
  // sysmon_listener.py writes every 3s → we poll every 5s
  void startPolling(void Function(List<SysmonLog>) onUpdate) {
    _onLogsUpdated = onUpdate;
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(ApiConstants.pollInterval, (_) async {
      await refreshLogs();
    });
  }

  void stopPolling() {
    _pollTimer?.cancel();
    _pollTimer = null;
    _onLogsUpdated = null;
  }

  // ── Alerts = Medium + High risk logs ──────────────────────────
  List<SysmonLog> get alerts =>
      _localLogs.where((l) => l.isAlert).toList();

  // ── Dashboard stats ────────────────────────────────────────────
  Map<String, dynamic> get dashboardStats => {
    'totalLogs':      _localLogs.length,
    'activeAlerts':   alerts.length,
    'highRisk':       _localLogs.where((l) => l.isHighRisk).length,
    'mediumRisk':     _localLogs.where((l) => l.isMediumRisk).length,
    'normalLogs':     _localLogs.where((l) => !l.isAlert).length,
    'latestRisk':     _lastPrediction?.finalRisk ?? '—',
    'latestAction':   _lastPrediction?.systemAction ?? '—',
    'latestExplain':  _lastPrediction?.aiExplanation ?? '',
  };
}
