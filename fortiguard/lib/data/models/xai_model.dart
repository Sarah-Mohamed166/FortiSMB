// lib/data/models/xai_model.dart
// SOURCE: main.py → final_result["ai_explanation"] = llm_service.explain_risk(...)
//         llm_service.py → Gemini 2.0 Flash model
//         m1.py / m2.py → probabilities used as SHAP-like indicators

import 'prediction_response.dart';

class XAIExplanationModel {
  /// The Gemini 2.0 Flash explanation (from ai_explanation field)
  final String geminiExplanation;

  /// Stage 1 output (M1 Random Forest — Low vs Elevated)
  final StageResult? stage1;

  /// Stage 2 output (M2 — Medium vs High), null if stage1 = Low
  final StageResult? stage2;

  /// Final risk level
  final String finalRisk;

  /// System action recommended
  final String systemAction;

  /// The original event that was analysed
  final String aiQuery;
  final String action;
  final String role;
  final String fileOp;
  final bool isUsb;
  final double hour;
  final bool offHours;

  const XAIExplanationModel({
    required this.geminiExplanation,
    this.stage1,
    this.stage2,
    required this.finalRisk,
    required this.systemAction,
    required this.aiQuery,
    required this.action,
    required this.role,
    required this.fileOp,
    required this.isUsb,
    required this.hour,
    required this.offHours,
  });

  factory XAIExplanationModel.fromPrediction(
    PredictionResponse resp, {
    Map<String, dynamic>? payload,
  }) {
    return XAIExplanationModel(
      geminiExplanation: resp.aiExplanation.isNotEmpty
          ? resp.aiExplanation
          : 'No explanation returned from backend.',
      stage1:       resp.stage1,
      stage2:       resp.stage2,
      finalRisk:    resp.finalRisk,
      systemAction: resp.systemAction,
      aiQuery:      payload?['ai_query']?.toString()     ?? resp.aiQuery,
      action:       payload?['action']?.toString()        ?? '',
      role:         payload?['fortismb_role']?.toString() ?? '',
      fileOp:       payload?['file_op']?.toString()       ?? '',
      isUsb:        payload?['is_usb'] == true,
      hour:         (payload?['hour'] as num?)?.toDouble() ?? 0,
      offHours:     payload?['off_hours'] == true,
    );
  }

  bool get hasGemini  => geminiExplanation.isNotEmpty && geminiExplanation != 'No explanation returned from backend.';
  bool get stage2Ran  => stage2 != null;

  /// Risk factors derived from model probabilities + event fields
  List<_RiskFactor> get riskFactors {
    final factors = <_RiskFactor>[];

    if (isUsb) {
      factors.add(const _RiskFactor(
        label: 'USB / Removable Media',
        description: 'USB device involvement detected',
        impact: 'HIGH',
        weight: 0.31,
      ));
    }
    if (offHours) {
      factors.add(const _RiskFactor(
        label: 'Off-Hours Activity',
        description: 'Event occurred outside 08:00–18:00',
        impact: 'HIGH',
        weight: 0.24,
      ));
    }
    if (action == 'device') {
      factors.add(const _RiskFactor(
        label: 'Device / USB Action',
        description: 'Sysmon Event ID 1 — process/device creation',
        impact: 'MEDIUM',
        weight: 0.18,
      ));
    }
    if (hour > 18 || hour < 8) {
      factors.add(_RiskFactor(
        label: 'Suspicious Hour: ${hour.toInt()}:00',
        description: 'Outside normal business hours',
        impact: 'MEDIUM',
        weight: 0.12,
      ));
    }
    if (fileOp == 'copy' || fileOp == 'write') {
      factors.add(_RiskFactor(
        label: 'File Operation: $fileOp',
        description: 'Data transfer or modification detected',
        impact: 'MEDIUM',
        weight: 0.10,
      ));
    }
    if (stage1 != null) {
      factors.add(_RiskFactor(
        label: 'M1 Anomaly Score',
        description: 'Random Forest: ${stage1!.label} (${stage1!.confidenceText})',
        impact: stage1!.label == 'Elevated' ? 'HIGH' : 'LOW',
        weight: stage1!.primaryProb,
      ));
    }
    return factors;
  }
}

class _RiskFactor {
  final String label;
  final String description;
  final String impact;   // "HIGH" | "MEDIUM" | "LOW"
  final double weight;   // 0.0 – 1.0

  const _RiskFactor({
    required this.label,
    required this.description,
    required this.impact,
    required this.weight,
  });

  double get pct => (weight * 100).clamp(0, 100);
}

// expose _RiskFactor publicly
typedef RiskFactor = _RiskFactor;
