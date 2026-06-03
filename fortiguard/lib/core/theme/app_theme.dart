import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../constants/app_colors.dart';

class AppTheme {
  AppTheme._();
  static ThemeData get dark => ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    scaffoldBackgroundColor: AppColors.bgPrimary,
    fontFamily: 'Inter',
    colorScheme: const ColorScheme.dark(
      primary: AppColors.cyan, secondary: AppColors.purple,
      surface: AppColors.surface1, error: AppColors.riskHigh,
      onPrimary: AppColors.bgPrimary, onSurface: AppColors.textPrimary,
    ),
    appBarTheme: const AppBarTheme(
      backgroundColor: AppColors.headerBg, foregroundColor: AppColors.textPrimary,
      elevation: 0, centerTitle: false,
      systemOverlayStyle: SystemUiOverlayStyle(
        statusBarColor: Colors.transparent,
        statusBarIconBrightness: Brightness.light,
      ),
      titleTextStyle: TextStyle(fontFamily:'Inter', fontSize:14,
          fontWeight:FontWeight.w600, color:AppColors.textPrimary),
    ),
    cardTheme: CardThemeData(
      color: AppColors.surface1, elevation: 0, margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(10),
        side: const BorderSide(color: AppColors.border),
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true, fillColor: AppColors.surface1,
      hintStyle: const TextStyle(fontFamily:'Inter', fontSize:11, color:AppColors.textDim),
      contentPadding: const EdgeInsets.symmetric(horizontal:14, vertical:12),
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color:AppColors.border)),
      enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color:AppColors.border, width:1.5)),
      focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color:AppColors.cyan, width:1.5)),
      errorBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color:AppColors.riskHigh)),
    ),
    elevatedButtonTheme: ElevatedButtonThemeData(style: ElevatedButton.styleFrom(
      backgroundColor: AppColors.cyan, foregroundColor: AppColors.bgPrimary,
      minimumSize: const Size.fromHeight(46), elevation: 0,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
      textStyle: const TextStyle(fontFamily:'Inter', fontSize:13, fontWeight:FontWeight.w700),
    )),
    outlinedButtonTheme: OutlinedButtonThemeData(style: OutlinedButton.styleFrom(
      foregroundColor: AppColors.textSub, minimumSize: const Size.fromHeight(44),
      side: const BorderSide(color: AppColors.border),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
    )),
    switchTheme: SwitchThemeData(
      thumbColor: WidgetStateProperty.resolveWith((s)=>s.contains(WidgetState.selected)?AppColors.cyan:AppColors.textDim),
      trackColor: WidgetStateProperty.resolveWith((s)=>s.contains(WidgetState.selected)?AppColors.cyan.withOpacity(0.3):AppColors.surface2),
    ),
    dividerTheme: const DividerThemeData(color:AppColors.border, thickness:1, space:1),
  );
}