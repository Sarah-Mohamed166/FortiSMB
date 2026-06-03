import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../core/constants/app_colors.dart';
import '../../data/repositories/app_provider.dart';
import '../widgets/shared_widgets.dart';

class ProfileScreen extends StatefulWidget {
  const ProfileScreen({super.key});

  @override
  State<ProfileScreen> createState() => _State();
}

class _State extends State<ProfileScreen> {
  int _nav = 4;

  bool _mfa = true;
  bool _bio = true;
  bool _dark = true;
  bool _push = true;
  bool _email = false;

  void _goBack(BuildContext ctx) {
    if (Navigator.canPop(ctx)) {
      Navigator.pop(ctx);
    } else {
      Navigator.pushReplacementNamed(ctx, '/dashboard');
    }
  }

  @override
  Widget build(BuildContext ctx) {
    final auth = ctx.read<AuthProvider>();
    final logs = ctx.watch<LogsProvider>();

    return Scaffold(
      backgroundColor: AppColors.bgPrimary,
      body: Column(
        children: [
          const FortiStatusBar(),

          Container(
            height: 52,
            color: AppColors.headerBg,
            padding: const EdgeInsets.symmetric(horizontal: 8),
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
                  'Profile & Settings',
                  style: TextStyle(
                    fontFamily: 'Inter',
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                    color: AppColors.textPrimary,
                  ),
                ),
              ],
            ),
          ),

          ServerStatusBanner(isUp: logs.serverUp),

          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(14),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Center(
                    child: Column(
                      children: [
                        const SizedBox(height: 10),
                        Container(
                          width: 120,
                          height: 120,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: Colors.white.withOpacity(0.03),
                            boxShadow: [
                              BoxShadow(
                                color: AppColors.cyan.withOpacity(0.15),
                                blurRadius: 30,
                                spreadRadius: 2,
                              ),
                            ],
                          ),
                          child: Padding(
                            padding: const EdgeInsets.all(12),
                            child: Image.asset(
                              'assets/images/fortismb_logo.png',
                              fit: BoxFit.contain,
                            ),
                          ),
                        ),
                        const SizedBox(height: 16),
                        Text(
                          auth.role ?? 'Security Analyst',
                          style: const TextStyle(
                            fontFamily: 'Inter',
                            fontSize: 18,
                            fontWeight: FontWeight.w700,
                            color: AppColors.textPrimary,
                          ),
                        ),
                        const SizedBox(height: 4),
                        const Text(
                          'SOC Team  •  Full Access',
                          style: TextStyle(
                            fontFamily: 'Inter',
                            fontSize: 10,
                            color: AppColors.textSub,
                          ),
                        ),
                        const SizedBox(height: 10),
                        Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 14,
                            vertical: 5,
                          ),
                          decoration: BoxDecoration(
                            color: AppColors.cyan.withOpacity(0.10),
                            borderRadius: BorderRadius.circular(100),
                            border: Border.all(
                              color: AppColors.cyan.withOpacity(0.4),
                            ),
                          ),
                          child: const Text(
                            '● FULL ACCESS',
                            style: TextStyle(
                              fontFamily: 'Inter',
                              fontSize: 9,
                              fontWeight: FontWeight.w700,
                              color: AppColors.cyan,
                            ),
                          ),
                        ),
                        const SizedBox(height: 20),
                      ],
                    ),
                  ),

                  const Divider(color: AppColors.border),
                  const SizedBox(height: 16),

                  _sect('Account Info'),
                  _row('Employee ID', auth.empId),
                  _row('Role', auth.role ?? '—'),
                  _row('Department', 'SOC Security Team'),
                  _row('Last Login', 'Today 09:41 AM'),
                  _row('Server', 'http://10.0.2.2:8000'),
                  _row('Logs Collected', '${logs.logs.length}'),
                  _row('Active Alerts', '${logs.alerts.length}'),

                  const SizedBox(height: 18),

                  _sect('Security'),
                  _toggle('MFA Authentication', _mfa, (v) {
                    setState(() => _mfa = v);
                  }),
                  _toggle('Biometric Login', _bio, (v) {
                    setState(() => _bio = v);
                  }),
                  _item('Session Timeout', '30 min'),

                  const SizedBox(height: 18),

                  _sect('Appearance'),
                  _toggle('Dark Mode', _dark, (v) {
                    setState(() => _dark = v);
                  }),
                  _item('Language', 'English'),

                  const SizedBox(height: 18),

                  _sect('Notifications'),
                  _toggle('Push Security Alerts', _push, (v) {
                    setState(() => _push = v);
                  }),
                  _toggle('Email Summary', _email, (v) {
                    setState(() => _email = v);
                  }),

                  const SizedBox(height: 18),

                  _sect('Backend Connection'),
                  _row('API Base URL', 'http://10.0.2.2:8000'),
                  _row('ClickHouse', 'http://10.0.2.2:8123'),
                  _row(
                    'FastAPI Status',
                    logs.serverUp ? '✓ Connected' : '✗ Offline',
                  ),

                  const SizedBox(height: 20),

                  GestureDetector(
                    onTap: () {
                      ctx.read<AuthProvider>().logout();
                      Navigator.pushReplacementNamed(ctx, '/login');
                    },
                    child: Container(
                      width: double.infinity,
                      padding: const EdgeInsets.symmetric(vertical: 13),
                      decoration: BoxDecoration(
                        color: AppColors.riskHigh.withOpacity(0.08),
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(
                          color: AppColors.riskHigh.withOpacity(0.35),
                        ),
                      ),
                      child: const Center(
                        child: Text(
                          'Logout',
                          style: TextStyle(
                            fontFamily: 'Inter',
                            fontSize: 12,
                            fontWeight: FontWeight.w700,
                            color: AppColors.riskHigh,
                          ),
                        ),
                      ),
                    ),
                  ),

                  const SizedBox(height: 12),

                  const Center(
                    child: Text(
                      'FortiSMB v2.0.0 • HIPAA Compliant',
                      style: TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 8,
                        color: AppColors.textDim,
                      ),
                    ),
                  ),

                  const SizedBox(height: 10),
                ],
              ),
            ),
          ),
        ],
      ),

      bottomNavigationBar: FortiBottomNav(
        idx: _nav,
        onTap: (i) {
          if (i == _nav) return;

          setState(() => _nav = i);

          switch (i) {
            case 0:
              Navigator.pushReplacementNamed(ctx, '/dashboard');
              break;
            case 1:
              Navigator.pushReplacementNamed(ctx, '/logs');
              break;
            case 2:
              Navigator.pushReplacementNamed(ctx, '/alerts');
              break;
            case 3:
              Navigator.pushReplacementNamed(ctx, '/risk');
              break;
          }
        },
      ),
    );
  }

  Widget _sect(String t) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Text(
          t,
          style: const TextStyle(
            fontFamily: 'Inter',
            fontSize: 10,
            fontWeight: FontWeight.w700,
            color: AppColors.cyan,
          ),
        ),
      );

  Widget _row(String k, String v) => Container(
        margin: const EdgeInsets.only(bottom: 6),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
        decoration: BoxDecoration(
          color: AppColors.surface1,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: AppColors.border),
        ),
        child: Row(
          children: [
            Expanded(
              child: Text(
                k,
                style: const TextStyle(
                  fontFamily: 'Inter',
                  fontSize: 10,
                  color: AppColors.textMuted,
                ),
              ),
            ),
            Text(
              v,
              style: const TextStyle(
                fontFamily: 'Inter',
                fontSize: 10,
                fontWeight: FontWeight.w600,
                color: AppColors.textPrimary,
              ),
            ),
          ],
        ),
      );

  Widget _toggle(String l, bool v, ValueChanged<bool> fn) => SwitchListTile(
        value: v,
        onChanged: fn,
        title: Text(l),
      );

  Widget _item(String l, String v) => _row(l, v);
}