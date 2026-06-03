import 'package:flutter/material.dart';

class AppColors {
  AppColors._();
  static const Color bgPrimary   = Color(0xFF090D14);
  static const Color surface1    = Color(0xFF111827);
  static const Color surface2    = Color(0xFF0E1520);
  static const Color headerBg    = Color(0xFF0D1520);
  static const Color cyan        = Color(0xFF01D4FF);
  static const Color textPrimary = Color(0xFFEEF3FF);
  static const Color textSub     = Color(0xFFA6C2DF);
  static const Color textMuted   = Color(0xFF6B8299);
  static const Color textDim     = Color(0xFF596680);
  static const Color border      = Color(0xFF2D3F52);
  static const Color riskHigh    = Color(0xFFFF4444);
  static const Color riskMedium  = Color(0xFFFFB347);
  static const Color riskLow     = Color(0xFF3FB950);
  static const Color purple      = Color(0xFFA371F7);
  static const Color gold        = Color(0xFFF0A500);
  static const Color blue        = Color(0xFF5896FF);

  static Color riskColor(String? risk) {
    switch ((risk ?? '').toLowerCase()) {
      case 'high':   return riskHigh;
      case 'medium': return riskMedium;
      case 'low':    return riskLow;
      default:       return textMuted;
    }
  }

  static Color actionColor(String? action) {
    final a = (action ?? '').toLowerCase();
    if (a.contains('block'))   return riskHigh;
    if (a.contains('alert'))   return riskMedium;
    if (a.contains('monitor')) return riskLow;
    return textMuted;
  }
}