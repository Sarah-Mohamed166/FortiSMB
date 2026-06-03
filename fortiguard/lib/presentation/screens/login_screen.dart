import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../core/constants/app_colors.dart';
import '../../data/repositories/app_provider.dart';
import '../widgets/shared_widgets.dart';

const _roles = [
  'Security Analyst',
];

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _State();
}

class _State extends State<LoginScreen> {
  final _empCtrl =
      TextEditingController(text: 'EMP-2024-0082');

  final _passCtrl = TextEditingController();

  bool _hide = true;
  bool _loading = false;
  bool _remember = false;

  String _role = _roles[0];
  String? _err;

  @override
  void dispose() {
    _empCtrl.dispose();
    _passCtrl.dispose();
    super.dispose();
  }

  Future<void> _login() async {
    if (_empCtrl.text.isEmpty || _passCtrl.text.isEmpty) {
      setState(() {
        _err = 'Please fill in all fields.';
      });
      return;
    }

    setState(() {
      _loading = true;
      _err = null;
    });

    final ok = await context.read<AuthProvider>().loginReal(
          employeeId: _empCtrl.text.trim(),
          password: _passCtrl.text.trim(),
        );

    if (!mounted) return;

    setState(() => _loading = false);

    if (ok) {
      Navigator.pushReplacementNamed(context, '/dashboard');
    } else {
      setState(() {
        _err = context.read<AuthProvider>().error ?? 'Login failed.';
      });
    }
  }

  @override
  Widget build(BuildContext ctx) => Scaffold(
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
                size: 240,
                opacity: 0.07,
              ),
            ),

            SafeArea(
              child: SingleChildScrollView(
                padding: const EdgeInsets.symmetric(
                  horizontal: 22,
                  vertical: 12,
                ),
                child: Column(
                  crossAxisAlignment:
                      CrossAxisAlignment.start,
                  children: [
                    const SizedBox(height: 18),

                    /// LOGO SECTION
                    Center(
                      child: Column(
                        children: [
                          Container(
                            width: 130,
                            height: 130,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              color: Colors.white
                                  .withOpacity(0.03),
                              boxShadow: [
                                BoxShadow(
                                  color: AppColors.cyan
                                      .withOpacity(
                                          0.15),
                                  blurRadius: 30,
                                  spreadRadius: 2,
                                ),
                              ],
                            ),
                            child: Padding(
                              padding:
                                  const EdgeInsets
                                      .all(10),
                              child: Image.asset(
                                'assets/images/fortismb_logo.png',
                                fit: BoxFit.contain,
                              ),
                            ),
                          ),

                          const SizedBox(height: 14),

                          const Text(
                            'FortiSMB',
                            style: TextStyle(
                              fontFamily: 'Inter',
                              fontSize: 24,
                              fontWeight:
                                  FontWeight.w800,
                              color: AppColors
                                  .textPrimary,
                            ),
                          ),

                          const SizedBox(height: 4),

                          const Text(
                            'Security Analyst Authentication',
                            style: TextStyle(
                              fontFamily: 'Inter',
                              fontSize: 11,
                              color:
                                  AppColors.textSub,
                            ),
                          ),
                        ],
                      ),
                    ),

                    const SizedBox(height: 30),

                    _lbl('EMPLOYEE ID'),
                    const SizedBox(height: 5),

                    TextField(
                      controller: _empCtrl,
                      style: const TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 11,
                        color:
                            AppColors.textPrimary,
                      ),
                      decoration:
                          _dec('EMP-2024-XXXX'),
                    ),

                    const SizedBox(height: 14),

                    _lbl('PASSWORD'),
                    const SizedBox(height: 5),

                    TextField(
                      controller: _passCtrl,
                      obscureText: _hide,
                      style: const TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 11,
                        color:
                            AppColors.textPrimary,
                      ),
                      decoration: _dec(
                        '••••••••••',
                      ).copyWith(
                        suffixIcon: IconButton(
                          icon: Icon(
                            _hide
                                ? Icons
                                    .visibility_off_outlined
                                : Icons
                                    .visibility_outlined,
                            color:
                                AppColors.textMuted,
                            size: 16,
                          ),
                          onPressed: () {
                            setState(() {
                              _hide = !_hide;
                            });
                          },
                        ),
                      ),
                    ),

                    const SizedBox(height: 14),

                    _lbl('ROLE'),
                    const SizedBox(height: 5),

                    Container(
                      decoration: BoxDecoration(
                        color:
                            AppColors.surface1,
                        borderRadius:
                            BorderRadius
                                .circular(8),
                        border: Border.all(
                          color: AppColors.cyan
                              .withOpacity(0.45),
                          width: 1.5,
                        ),
                      ),
                      child:
                          DropdownButtonHideUnderline(
                        child:
                            DropdownButton<String>(
                          value: _role,
                          isExpanded: true,
                          padding:
                              const EdgeInsets
                                  .symmetric(
                            horizontal: 12,
                          ),
                          dropdownColor:
                              AppColors.surface1,
                          style:
                              const TextStyle(
                            fontFamily: 'Inter',
                            fontSize: 11,
                            color:
                                AppColors.cyan,
                          ),
                          icon: const Icon(
                            Icons
                                .keyboard_arrow_down,
                            color: AppColors
                                .textMuted,
                            size: 16,
                          ),
                          items: _roles
                              .map(
                                (r) =>
                                    DropdownMenuItem(
                                  value: r,
                                  child: Text(r),
                                ),
                              )
                              .toList(),
                          onChanged: (v) {
                            if (v != null) {
                              setState(() {
                                _role = v;
                              });
                            }
                          },
                        ),
                      ),
                    ),

                    const SizedBox(height: 14),

                    Row(
                      children: [
                        GestureDetector(
                          onTap: () {
                            setState(() {
                              _remember =
                                  !_remember;
                            });
                          },
                          child: Row(
                            children: [
                              Container(
                                width: 15,
                                height: 15,
                                decoration:
                                    BoxDecoration(
                                  borderRadius:
                                      BorderRadius
                                          .circular(
                                              3),
                                  color: _remember
                                      ? AppColors
                                          .cyan
                                          .withOpacity(
                                              0.14)
                                      : AppColors
                                          .surface1,
                                  border:
                                      Border.all(
                                    color: _remember
                                        ? AppColors
                                            .cyan
                                        : AppColors
                                            .border,
                                  ),
                                ),
                                child: _remember
                                    ? const Icon(
                                        Icons
                                            .check,
                                        size: 10,
                                        color:
                                            AppColors
                                                .cyan,
                                      )
                                    : null,
                              ),

                              const SizedBox(
                                  width: 7),

                              const Text(
                                'Remember this device',
                                style:
                                    TextStyle(
                                  fontFamily:
                                      'Inter',
                                  fontSize:
                                      10,
                                  color:
                                      AppColors
                                          .textSub,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),

                    const SizedBox(height: 22),

                    if (_err != null) ...[
                      Text(
                        _err!,
                        style:
                            const TextStyle(
                          color:
                              AppColors.riskHigh,
                        ),
                      ),
                      const SizedBox(
                          height: 12),
                    ],

                    SizedBox(
                      width: double.infinity,
                      height: 46,
                      child: ElevatedButton(
                        onPressed: _loading
                            ? null
                            : _login,
                        child: _loading
                            ? const CircularProgressIndicator()
                            : const Text(
                                'Authenticate Securely',
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

  InputDecoration _dec(String h) =>
      InputDecoration(hintText: h);
}