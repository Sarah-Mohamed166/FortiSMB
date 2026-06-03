// lib/main.dart
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import 'core/theme/app_theme.dart';
import 'data/repositories/app_provider.dart';

// Screens
import 'presentation/screens/splash_screen.dart';
import 'presentation/screens/onboarding_screen.dart';
import 'presentation/screens/login_screen.dart';
import 'presentation/screens/signup_screen.dart';
import 'presentation/screens/role_check_screen.dart';
import 'presentation/screens/dashboard_screen.dart';
import 'presentation/screens/logs_screen.dart';
import 'presentation/screens/alerts_screen.dart';
import 'presentation/screens/alert_detail_screen.dart';
import 'presentation/screens/risk_analysis_screen.dart';
import 'presentation/screens/xai_screen.dart';
import 'presentation/screens/profile_screen.dart';
import 'presentation/screens/access_denied_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
    DeviceOrientation.portraitDown,
  ]);

  SystemChrome.setSystemUIOverlayStyle(const SystemUiOverlayStyle(
    statusBarColor:                    Colors.transparent,
    statusBarIconBrightness:           Brightness.light,
    systemNavigationBarColor:          Color(0xFF090D14),
    systemNavigationBarIconBrightness: Brightness.light,
  ));

  runApp(
    MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => AuthProvider()),
        ChangeNotifierProvider(create: (_) => PredictionProvider()),
        ChangeNotifierProvider(create: (_) => LogsProvider()),
      ],
      child: const FortiGuardApp(),
    ),
  );
}

class FortiGuardApp extends StatelessWidget {
  const FortiGuardApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title:                      'FortiGuard',
      debugShowCheckedModeBanner: false,
      theme:                      AppTheme.dark,
      initialRoute:               '/',
      routes: {
        '/':             (_) => const SplashScreen(),
        '/onboarding':   (_) => const OnboardingScreen(),
        '/login':        (_) => const LoginScreen(),
        '/signup':       (_) => const SignUpScreen(),
        '/role-check':   (_) => const RoleCheckScreen(),
        '/dashboard':    (_) => const DashboardScreen(),
        '/logs':         (_) => const LogsScreen(),
        '/alerts':       (_) => const AlertsScreen(),
        '/alert-detail': (_) => const AlertDetailScreen(),
        '/risk':         (_) => const RiskAnalysisScreen(),
        '/xai':          (_) => const XAIScreen(),
        '/profile':      (_) => const ProfileScreen(),
        '/access-denied':(_) => const AccessDeniedScreen(),
      },
    );
  }
}
