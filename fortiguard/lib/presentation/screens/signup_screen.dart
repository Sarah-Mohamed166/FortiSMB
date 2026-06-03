import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../data/repositories/app_provider.dart';
import '../../core/constants/app_colors.dart';
import '../widgets/shared_widgets.dart';

class SignUpScreen extends StatefulWidget {
  const SignUpScreen({super.key});

  @override
  State<SignUpScreen> createState() => _State();
}

class _State extends State<SignUpScreen> {
  final _name = TextEditingController();
  final _emp = TextEditingController();
  final _email = TextEditingController();
  final _pass = TextEditingController();
  final _pass2 = TextEditingController();

  bool _hide = true;
  bool _loading = false;
  String? _err;

  void _goBack(BuildContext ctx) {
    if (Navigator.canPop(ctx)) {
      Navigator.pop(ctx);
    } else {
      Navigator.pushReplacementNamed(ctx, '/login');
    }
  }

  Future<void> _register() async {
    if ([
      _name,
      _emp,
      _email,
      _pass,
    ].any((c) => c.text.isEmpty)) {
      setState(() => _err = 'Please fill all required fields.');
      return;
    }

    if (_pass.text != _pass2.text) {
      setState(() => _err = 'Passwords do not match.');
      return;
    }

    if (_pass.text.length < 8) {
      setState(() => _err = 'Password must be at least 8 characters.');
      return;
    }

    setState(() {
      _loading = true;
      _err = null;
    });

    final ok = await context.read<AuthProvider>().signup(
          fullName: _name.text.trim(),
          employeeId: _emp.text.trim(),
          email: _email.text.trim(),
          password: _pass.text.trim(),
        );

    if (!mounted) return;

    setState(() => _loading = false);

    if (ok) {
      Navigator.pushReplacementNamed(context, '/login');
    } else {
      setState(() {
        _err = context.read<AuthProvider>().error ?? 'Signup failed.';
      });
    }
  }

  @override
  void dispose() {
    for (final c in [
      _name,
      _emp,
      _email,
      _pass,
      _pass2,
    ]) {
      c.dispose();
    }

    super.dispose();
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

          SafeArea(
            child: SingleChildScrollView(
              padding: const EdgeInsets.symmetric(
                horizontal: 22,
                vertical: 10,
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    height: 52,
                    color: Colors.transparent,
                    child: Row(
                      children: [
                        IconButton(
                          icon: const Icon(
                            Icons.arrow_back_ios_new,
                            size: 18,
                            color: AppColors.textPrimary,
                          ),
                          onPressed: () => _goBack(ctx),
                        ),
                        const Text(
                          'Back',
                          style: TextStyle(
                            fontFamily: 'Inter',
                            fontSize: 12,
                            color: AppColors.textSub,
                          ),
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 12),

                  const Text(
                    'Create Account',
                    style: TextStyle(
                      fontFamily: 'Inter',
                      fontSize: 24,
                      fontWeight: FontWeight.w800,
                      color: AppColors.textPrimary,
                    ),
                  ),

                  const SizedBox(height: 4),

                  const Text(
                    'Register your FortiSMB account',
                    style: TextStyle(
                      fontFamily: 'Inter',
                      fontSize: 11,
                      color: AppColors.textSub,
                    ),
                  ),

                  const SizedBox(height: 28),

                  _lbl('FULL NAME *'),
                  const SizedBox(height: 5),
                  TextField(
                    controller: _name,
                    style: _ts,
                    decoration: _d('Alex Johnson'),
                  ),

                  const SizedBox(height: 14),

                  _lbl('EMPLOYEE ID *'),
                  const SizedBox(height: 5),
                  TextField(
                    controller: _emp,
                    style: _ts,
                    decoration: _d('EMP-2024-XXXX'),
                  ),

                  const SizedBox(height: 14),

                  _lbl('EMAIL *'),
                  const SizedBox(height: 5),
                  TextField(
                    controller: _email,
                    style: _ts,
                    keyboardType: TextInputType.emailAddress,
                    decoration: _d('you@company.com'),
                  ),

                  const SizedBox(height: 14),

                  _lbl('APP ACCESS ROLE'),
                  const SizedBox(height: 5),

                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.symmetric(
                      horizontal: 14,
                      vertical: 13,
                    ),
                    decoration: BoxDecoration(
                      color: AppColors.surface1,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(
                        color: AppColors.cyan.withOpacity(0.45),
                        width: 1.5,
                      ),
                    ),
                    child: const Text(
                      'Security Analyst',
                      style: TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                        color: AppColors.cyan,
                      ),
                    ),
                  ),

                  const SizedBox(height: 14),

                  _lbl('PASSWORD *'),
                  const SizedBox(height: 5),

                  TextField(
                    controller: _pass,
                    style: _ts,
                    obscureText: _hide,
                    decoration: _d('Min 8 characters').copyWith(
                      suffixIcon: IconButton(
                        icon: Icon(
                          _hide
                              ? Icons.visibility_off_outlined
                              : Icons.visibility_outlined,
                          color: AppColors.textMuted,
                          size: 16,
                        ),
                        onPressed: () {
                          setState(() => _hide = !_hide);
                        },
                      ),
                    ),
                  ),

                  const SizedBox(height: 14),

                  _lbl('CONFIRM PASSWORD *'),
                  const SizedBox(height: 5),

                  TextField(
                    controller: _pass2,
                    style: _ts,
                    obscureText: true,
                    decoration: _d('Repeat password'),
                  ),

                  const SizedBox(height: 22),

                  if (_err != null) ...[
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: AppColors.riskHigh.withOpacity(0.09),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(
                          color: AppColors.riskHigh.withOpacity(0.35),
                        ),
                      ),
                      child: Text(
                        _err!,
                        style: const TextStyle(
                          fontFamily: 'Inter',
                          fontSize: 11,
                          color: AppColors.riskHigh,
                        ),
                      ),
                    ),
                    const SizedBox(height: 12),
                  ],

                  SizedBox(
                    width: double.infinity,
                    height: 46,
                    child: ElevatedButton(
                      onPressed: _loading ? null : _register,
                      child: _loading
                          ? const SizedBox(
                              width: 18,
                              height: 18,
                              child: CircularProgressIndicator(
                                color: AppColors.bgPrimary,
                                strokeWidth: 2,
                              ),
                            )
                          : const Text(
                              'Create Account',
                              style: TextStyle(
                                fontFamily: 'Inter',
                                fontSize: 13,
                                fontWeight: FontWeight.w700,
                                color: AppColors.bgPrimary,
                              ),
                            ),
                    ),
                  ),

                  const SizedBox(height: 12),

                  Center(
                    child: GestureDetector(
                      onTap: () {
                        Navigator.pushReplacementNamed(ctx, '/login');
                      },
                      child: RichText(
                        text: const TextSpan(
                          text: 'Already have an account? ',
                          style: TextStyle(
                            fontFamily: 'Inter',
                            fontSize: 11,
                            color: AppColors.textMuted,
                          ),
                          children: [
                            TextSpan(
                              text: 'Login',
                              style: TextStyle(
                                color: AppColors.cyan,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  TextStyle get _ts => const TextStyle(
        fontFamily: 'Inter',
        fontSize: 11,
        color: AppColors.textPrimary,
      );

  Widget _lbl(String t) => Text(
        t,
        style: const TextStyle(
          fontFamily: 'Inter',
          fontSize: 9,
          fontWeight: FontWeight.w600,
          color: AppColors.textDim,
          letterSpacing: 1.2,
        ),
      );

  InputDecoration _d(String h) => InputDecoration(
        hintText: h,
        hintStyle: const TextStyle(
          fontFamily: 'Inter',
          fontSize: 11,
          color: AppColors.textDim,
        ),
        filled: true,
        fillColor: AppColors.surface1,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 14,
          vertical: 12,
        ),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: AppColors.border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(
            color: AppColors.border,
            width: 1.5,
          ),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(
            color: AppColors.cyan,
            width: 1.5,
          ),
        ),
      );
}