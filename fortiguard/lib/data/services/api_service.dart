// lib/data/services/api_service.dart

import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

import '../../core/constants/api_constants.dart';
import '../../core/errors/app_error.dart';
import '../models/prediction_request.dart';
import '../models/prediction_response.dart';
import '../models/sysmon_log.dart';

class ApiService {
  ApiService._();

  static final ApiService instance = ApiService._();

  final http.Client _client = http.Client();

  Future<bool> isServerAlive() async {
    try {
      final uri = Uri.parse('${ApiConstants.baseUrl}${ApiConstants.health}');

      final resp = await _client
          .get(uri)
          .timeout(ApiConstants.connectTimeout);

      return resp.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  Future<Map<String, dynamic>> signup({
    required String fullName,
    required String employeeId,
    required String email,
    required String password,
  }) async {
    final uri = Uri.parse('${ApiConstants.baseUrl}${ApiConstants.signup}');

    final body = jsonEncode({
      'full_name': fullName,
      'employee_id': employeeId,
      'email': email,
      'password': password,
      'role': 'Security Analyst',
    });

    try {
      final resp = await _client
          .post(
            uri,
            headers: {'Content-Type': 'application/json'},
            body: body,
          )
          .timeout(ApiConstants.receiveTimeout);

      final json = _parseJson(resp.body);

      if (resp.statusCode == 200) {
        return json;
      }

      throw AppError(
        message: json['detail']?.toString() ?? 'Signup failed.',
        statusCode: resp.statusCode,
      );
    } on SocketException {
      throw AppError.connection();
    } on http.ClientException {
      throw AppError.connection();
    } on AppError {
      rethrow;
    } catch (e) {
      throw AppError(message: 'Signup error: $e');
    }
  }

  Future<Map<String, dynamic>> login({
    required String employeeId,
    required String password,
  }) async {
    final uri = Uri.parse('${ApiConstants.baseUrl}${ApiConstants.login}');

    final body = jsonEncode({
      'employee_id': employeeId,
      'password': password,
    });

    try {
      final resp = await _client
          .post(
            uri,
            headers: {'Content-Type': 'application/json'},
            body: body,
          )
          .timeout(ApiConstants.receiveTimeout);

      final json = _parseJson(resp.body);

      if (resp.statusCode == 200) {
        return json;
      }

      throw AppError(
        message: json['detail']?.toString() ?? 'Login failed.',
        statusCode: resp.statusCode,
      );
    } on SocketException {
      throw AppError.connection();
    } on http.ClientException {
      throw AppError.connection();
    } on AppError {
      rethrow;
    } catch (e) {
      throw AppError(message: 'Login error: $e');
    }
  }

  Future<PredictionResponse> predict(PredictionRequest req) async {
    final uri = Uri.parse('${ApiConstants.baseUrl}${ApiConstants.predict}');
    final body = jsonEncode(req.toJson());

    try {
      final resp = await _client
          .post(
            uri,
            headers: {'Content-Type': 'application/json'},
            body: body,
          )
          .timeout(ApiConstants.receiveTimeout);

      if (resp.statusCode == 200) {
        final json = _parseJson(resp.body);
        return PredictionResponse.fromJson(
          json,
          originalPayload: req.toJson(),
        );
      }

      if (resp.statusCode == 422) {
        final err = _parseJson(resp.body);

        throw AppError(
          message: 'Validation error: ${err['message'] ?? err.toString()}',
          statusCode: 422,
        );
      }

      throw AppError.server(resp.statusCode, resp.body);
    } on SocketException {
      throw AppError.connection();
    } on http.ClientException {
      throw AppError.connection();
    } on AppError {
      rethrow;
    } catch (e) {
      if (e.toString().contains('timeout') ||
          e.toString().contains('TimeoutException')) {
        throw AppError.timeout();
      }

      throw AppError(message: 'Unexpected error: $e');
    }
  }

  Future<List<SysmonLog>> fetchSysmonLogs({int limit = 100}) async {
    final query = Uri.encodeQueryComponent(
      'SELECT ai_query, action, role, file_op, is_usb, hour, '
      'off_hours, final_risk, system_action, explanation '
      'FROM ${ApiConstants.sysmonTable} '
      'ORDER BY rowNumberInAllBlocks() DESC '
      'LIMIT $limit '
      'FORMAT JSON',
    );

    final uri = Uri.parse(
      '${ApiConstants.clickhouseBase}/?query=$query'
      '&database=${ApiConstants.clickhouseDb}',
    );

    try {
      final resp = await _client
          .get(
            uri,
            headers: {
              'X-ClickHouse-User': ApiConstants.clickhouseUser,
              'X-ClickHouse-Key': ApiConstants.clickhousePass,
              'X-ClickHouse-Database': ApiConstants.clickhouseDb,
            },
          )
          .timeout(ApiConstants.receiveTimeout);

      if (resp.statusCode == 200) {
        final json = _parseJson(resp.body);
        final data = json['data'] as List? ?? [];

        return data
            .map(
              (row) => SysmonLog.fromClickHouseJson(
                row as Map<String, dynamic>,
              ),
            )
            .toList();
      }

      return [];
    } catch (_) {
      return [];
    }
  }

  Map<String, dynamic> _parseJson(String body) {
    try {
      return jsonDecode(body) as Map<String, dynamic>;
    } catch (_) {
      throw AppError(message: 'Invalid JSON response from server.');
    }
  }
}