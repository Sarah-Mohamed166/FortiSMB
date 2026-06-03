// lib/data/repositories/app_provider.dart

import 'package:flutter/foundation.dart';

import '../models/prediction_request.dart';
import '../models/prediction_response.dart';
import '../models/sysmon_log.dart';
import '../models/xai_model.dart';
import '../repositories/fortismb_repository.dart';
import '../services/api_service.dart';
import '../../core/errors/app_error.dart';

// ── Session / Auth state ───────────────────────────────────────
class AuthProvider extends ChangeNotifier {
  String? _role;
  String _name = 'Security Analyst';
  String _empId = 'EMP-0082';
  String _email = '';
  bool _isAnalyst = false;

  bool _loading = false;
  String? _error;

  String? get role => _role;
  String get name => _name;
  String get empId => _empId;
  String get email => _email;
  bool get isAnalyst => _isAnalyst;
  bool get isLoggedIn => _role != null;

  bool get loading => _loading;
  String? get error => _error;

  void login(
    String role, {
    String name = 'Security Analyst',
    String empId = 'EMP-0082',
    String email = '',
  }) {
    _role = role;
    _name = name;
    _empId = empId;
    _email = email;
    _isAnalyst = role == 'Security Analyst';
    _error = null;
    notifyListeners();
  }

  Future<bool> loginReal({
    required String employeeId,
    required String password,
  }) async {
    _loading = true;
    _error = null;
    notifyListeners();

    try {
      final user = await ApiService.instance.login(
        employeeId: employeeId,
        password: password,
      );

      login(
        user['role']?.toString() ?? 'Security Analyst',
        name: user['full_name']?.toString() ?? 'Security Analyst',
        empId: user['employee_id']?.toString() ?? employeeId,
        email: user['email']?.toString() ?? '',
      );

      _loading = false;
      _error = null;
      notifyListeners();
      return true;
    } on AppError catch (e) {
      _loading = false;
      _error = e.message;
      notifyListeners();
      return false;
    } catch (e) {
      _loading = false;
      _error = 'Login failed: $e';
      notifyListeners();
      return false;
    }
  }

  Future<bool> signup({
    required String fullName,
    required String employeeId,
    required String email,
    required String password,
  }) async {
    _loading = true;
    _error = null;
    notifyListeners();

    try {
      await ApiService.instance.signup(
        fullName: fullName,
        employeeId: employeeId,
        email: email,
        password: password,
      );

      _loading = false;
      _error = null;
      notifyListeners();
      return true;
    } on AppError catch (e) {
      _loading = false;
      _error = e.message;
      notifyListeners();
      return false;
    } catch (e) {
      _loading = false;
      _error = 'Signup failed: $e';
      notifyListeners();
      return false;
    }
  }

  void clearError() {
    _error = null;
    notifyListeners();
  }

  void logout() {
    _role = null;
    _name = 'Security Analyst';
    _empId = 'EMP-0082';
    _email = '';
    _isAnalyst = false;
    _error = null;
    notifyListeners();
  }
}

// ── Prediction provider ────────────────────────────────────────
class PredictionProvider extends ChangeNotifier {
  final _repo = FortiSMBRepository.instance;

  bool _loading = false;
  String? _error;
  PredictionResponse? _response;
  XAIExplanationModel? _xai;

  bool get loading => _loading;
  String? get error => _error;
  PredictionResponse? get response => _response;
  XAIExplanationModel? get xai => _xai;

  Future<void> predict({
    required String aiQuery,
    required String action,
    required String role,
    String fileOp = '',
    bool isUsb = false,
    required double hour,
    bool offHours = false,
    String? date,
  }) async {
    _loading = true;
    _error = null;
    notifyListeners();

    try {
      final req = PredictionRequest(
        aiQuery: aiQuery,
        action: action,
        fortismbRole: role,
        fileOp: fileOp,
        isUsb: isUsb,
        hour: hour,
        offHours: offHours,
        date: date,
      );

      _response = await _repo.predict(req);
      _xai = _repo.lastXAI;
      _error = null;
    } on AppError catch (e) {
      _error = e.message;
    } catch (e) {
      _error = 'Unexpected error: $e';
    } finally {
      _loading = false;
      notifyListeners();
    }
  }

  void clearError() {
    _error = null;
    notifyListeners();
  }
}

// ── Logs provider ──────────────────────────────────────────────
class LogsProvider extends ChangeNotifier {
  final _repo = FortiSMBRepository.instance;

  bool _loading = false;
  String? _error;
  List<SysmonLog> _logs = [];
  bool _serverUp = false;

  bool get loading => _loading;
  String? get error => _error;
  List<SysmonLog> get logs => _logs;
  bool get serverUp => _serverUp;

  List<SysmonLog> get alerts => _logs.where((l) => l.isAlert).toList();

  Map<String, dynamic> get stats => _repo.dashboardStats;

  List<SysmonLog> filtered(String filter) {
    switch (filter) {
      case 'High Risk':
        return _logs.where((l) => l.isHighRisk).toList();
      case 'Medium Risk':
        return _logs.where((l) => l.isMediumRisk).toList();
      case 'Normal':
        return _logs.where((l) => !l.isAlert).toList();
      default:
        return _logs;
    }
  }

  List<SysmonLog> search(List<SysmonLog> base, String q) {
    if (q.isEmpty) return base;

    final lq = q.toLowerCase();

    return base.where((l) {
      return l.role.toLowerCase().contains(lq) ||
          l.action.toLowerCase().contains(lq) ||
          l.aiQuery.toLowerCase().contains(lq) ||
          l.finalRisk.toLowerCase().contains(lq);
    }).toList();
  }

  Future<void> init() async {
    _serverUp = await _repo.isServerAlive();
    await refresh();

    _repo.startPolling((updated) {
      _logs = updated;
      notifyListeners();
    });
  }

  Future<void> refresh() async {
    _loading = true;
    notifyListeners();

    try {
      _logs = await _repo.refreshLogs();
      _error = null;
    } on AppError catch (e) {
      _error = e.message;
    } catch (e) {
      _error = e.toString();
    } finally {
      _loading = false;
      notifyListeners();
    }
  }

  @override
  void dispose() {
    _repo.stopPolling();
    super.dispose();
  }
}