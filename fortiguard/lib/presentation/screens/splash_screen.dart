import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../core/constants/app_colors.dart';
import '../../data/repositories/app_provider.dart';
import '../../data/repositories/fortismb_repository.dart';
import '../widgets/shared_widgets.dart';

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _State();
}

class _State extends State<SplashScreen>
    with SingleTickerProviderStateMixin {
  late AnimationController _c;
  late Animation<double> _fade;
  late Animation<double> _scale;

  @override
  void initState() {
    super.initState();

    _c = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1000),
    );

    _fade = CurvedAnimation(
      parent: _c,
      curve: Curves.easeIn,
    );

    _scale = Tween<double>(
      begin: 0.88,
      end: 1.0,
    ).animate(
      CurvedAnimation(
        parent: _c,
        curve: Curves.easeOutCubic,
      ),
    );

    _c.forward();

    Future.delayed(
      const Duration(seconds: 3),
      _navigate,
    );
  }

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  Future<void> _navigate() async {
    if (!mounted) return;

    final logs = context.read<LogsProvider>();

    await logs.init();

    if (!mounted) return;

    Navigator.of(context)
        .pushReplacementNamed('/onboarding');
  }

  @override
  Widget build(BuildContext ctx) {
    return Scaffold(
      backgroundColor: AppColors.bgPrimary,
      body: Stack(
        children: [
          CustomPaint(
            painter: GridPainter(),
            size: Size.infinite,
          ),

          Positioned(
            top: -40,
            left: -40,
            child: GlowOrb(
              color: AppColors.cyan,
              size: 280,
            ),
          ),

          Positioned(
            top: 200,
            right: -30,
            child: GlowOrb(
              color: AppColors.purple,
              size: 200,
              opacity: 0.06,
            ),
          ),

          SafeArea(
            child: FadeTransition(
              opacity: _fade,
              child: ScaleTransition(
                scale: _scale,
                child: Column(
                  mainAxisAlignment:
                      MainAxisAlignment.center,
                  children: [
                    /// LOGO
                    Center(
                      child: Container(
                        width: 190,
                        height: 190,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: Colors.white
                              .withOpacity(0.03),
                          boxShadow: [
                            BoxShadow(
                              color: AppColors.cyan
                                  .withOpacity(0.12),
                              blurRadius: 35,
                              spreadRadius: 5,
                            ),
                          ],
                        ),
                        child: Padding(
                          padding:
                              const EdgeInsets.all(10),
                          child: Image.asset(
                            'assets/images/fortismb_logo.png',
                            fit: BoxFit.contain,
                          ),
                        ),
                      ),
                    ),

                    const SizedBox(height: 28),

                    /// TITLE
                    const Text(
                      'FortiSMB',
                      style: TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 34,
                        fontWeight:
                            FontWeight.w800,
                        color:
                            AppColors.textPrimary,
                        letterSpacing: -0.8,
                      ),
                    ),

                    const SizedBox(height: 10),

                    /// SUBTITLE
                    const Text(
                      'AI-Driven Insider Threat Detection',
                      textAlign:
                          TextAlign.center,
                      style: TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 13,
                        fontWeight:
                            FontWeight.w400,
                        color:
                            AppColors.cyan,
                        letterSpacing: 0.3,
                      ),
                    ),

                    const SizedBox(height: 6),

                    const Text(
                      'Shielding SMBs In The Digital Battlefield',
                      textAlign:
                          TextAlign.center,
                      style: TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 10,
                        color:
                            AppColors.textMuted,
                      ),
                    ),

                    const SizedBox(height: 48),

                    /// LOADING DOTS
                    Row(
                      mainAxisSize:
                          MainAxisSize.min,
                      children: List.generate(
                        3,
                        (i) => Container(
                          margin:
                              const EdgeInsets.symmetric(
                            horizontal: 5,
                          ),
                          width: 8,
                          height: 8,
                          decoration: BoxDecoration(
                            shape:
                                BoxShape.circle,
                            color: AppColors
                                .cyan
                                .withOpacity(
                              0.25 +
                                  i * 0.28,
                            ),
                          ),
                        ),
                      ),
                    ),

                    const SizedBox(height: 48),

                    const Text(
                      'v2.0.0',
                      style: TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 9,
                        color:
                            AppColors.textDim,
                      ),
                    ),

                    const SizedBox(height: 8),

                    Container(
                      padding:
                          const EdgeInsets.symmetric(
                        horizontal: 14,
                        vertical: 5,
                      ),
                      decoration:
                          BoxDecoration(
                        border: Border.all(
                          color: AppColors
                              .border
                              .withOpacity(
                                  0.55),
                        ),
                        borderRadius:
                            BorderRadius
                                .circular(
                          100,
                        ),
                      ),
                      child: const Text(
                        '🔒 HIPAA • Explainable AI • FortiSMB v2.0',
                        style: TextStyle(
                          fontFamily:
                              'Inter',
                          fontSize: 9,
                          color:
                              AppColors
                                  .textDim,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}