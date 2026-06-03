// lib/data/models/prediction_response.dart
// SOURCE: main.py → @app.post("/predict") → final_result dict
//
// Real response structure:
// {
//   "ai_query":      string,
//   "date":          string | null,
//   "stage1": {
//     "model":       "M1",
//     "stage":       "Stage 1",
//     "prediction":  0 | 1,
//     "label":       "Low" | "Elevated",
//     "probabilities": {"Low": float, "Elevated": float}
//   },
//   "stage2": null | {
//     "model":       "M2",
//     "stage":       "Stage 2",
//     "prediction":  0 | 1,
//     "label":       "Medium" | "High",
//     "probabilities": {"Medium": float, "High": float} | null
//   },
//   "final_risk":    "Low" | "Medium" | "High",
//   "system_action": "Log & Monitor" | "Alert & Verify" | "Block & Mitigate",
//   "ai_explanation": string   (from Gemini 2.0 Flash)
// }

class StageResult {
  final String model;
  final String stage;
  final int prediction;
  final String label;
  final Map<String, double>? probabilities;

  const StageResult({
    required this.model,
    required this.stage,
    required this.prediction,
    required this.label,
    this.probabilities,
  });

  factory StageResult.fromJson(Map<String, dynamic> j) => StageResult(
    model:      j['model'] as String? ?? '',
    stage:      j['stage'] as String? ?? '',
    prediction: j['prediction'] as int? ?? 0,
    label:      j['label'] as String? ?? '',
    probabilities: (j['probabilities'] as Map?)?.map(
      (k, v) => MapEntry(k.toString(), (v as num).toDouble()),
    ),
  );

  /// Returns the primary probability (Elevated for M1, High for M2)
  double get primaryProb {
    if (probabilities == null) return 0;
    return probabilities!['Elevated'] ?? probabilities!['High'] ?? 0;
  }

  /// Returns human-readable confidence %
  String get confidenceText {
    final p = primaryProb;
    return '${(p * 100).toStringAsFixed(1)}%';
  }
}

class PredictionResponse {
  final String aiQuery;
  final String? date;
  final StageResult stage1;
  final StageResult? stage2;
  final String finalRisk;       // "Low" | "Medium" | "High"
  final String systemAction;    // "Log & Monitor" | "Alert & Verify" | "Block & Mitigate"
  final String aiExplanation;   // Gemini 2.0 Flash explanation

  /// The request payload (stored locally for display)
  final Map<String, dynamic>? originalPayload;

  const PredictionResponse({
    required this.aiQuery,
    this.date,
    required this.stage1,
    this.stage2,
    required this.finalRisk,
    required this.systemAction,
    required this.aiExplanation,
    this.originalPayload,
  });

  factory PredictionResponse.fromJson(
    Map<String, dynamic> j, {
    Map<String, dynamic>? originalPayload,
  }) {
    return PredictionResponse(
      aiQuery:       j['ai_query'] as String? ?? '',
      date:          j['date'] as String?,
      stage1:        StageResult.fromJson(j['stage1'] as Map<String, dynamic>? ?? {}),
      stage2:        j['stage2'] != null
          ? StageResult.fromJson(j['stage2'] as Map<String, dynamic>)
          : null,
      finalRisk:     j['final_risk'] as String? ?? 'Low',
      systemAction:  j['system_action'] as String? ?? 'Log & Monitor',
      aiExplanation: j['ai_explanation'] as String? ?? 'No explanation returned from backend.',
      originalPayload: originalPayload,
    );
  }

  bool get isHighRisk   => finalRisk.toLowerCase() == 'high';
  bool get isMediumRisk => finalRisk.toLowerCase() == 'medium';
  bool get isLowRisk    => finalRisk.toLowerCase() == 'low';

  /// Whether stage 2 ran (only when stage 1 = Elevated)
  bool get stage2Ran => stage2 != null;
}
