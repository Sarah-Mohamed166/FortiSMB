import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../core/constants/app_colors.dart';
import '../../data/repositories/app_provider.dart';
import '../widgets/shared_widgets.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _State();
}

class _State extends State<DashboardScreen> {
  int _nav = 0;

  final _chartH = [
    14, 20, 28, 18, 34, 26, 40, 32, 44, 36,
    48, 40, 52, 42, 48, 38, 44, 34, 40, 28,
    36, 24, 32, 20, 28, 18, 30, 22, 26, 16
  ];

  @override
  Widget build(BuildContext ctx) {
    final auth = ctx.read<AuthProvider>();
    final logs = ctx.watch<LogsProvider>();
    final stats = logs.stats;
    final recentLogs = logs.logs.take(4).toList();

    return Scaffold(
      backgroundColor: AppColors.bgPrimary,
      body: Column(
        children: [
          const FortiStatusBar(),

          Container(
            height: 50,
            color: AppColors.headerBg,
            padding: const EdgeInsets.symmetric(horizontal: 14),
            child: Row(
              children: [
                Image.asset(
                  'assets/images/fortismb_logo.png',
                  width: 34,
                  height: 34,
                  fit: BoxFit.contain,
                ),
                const SizedBox(width: 8),
                const Text(
                  'FortiSMB',
                  style: TextStyle(
                    fontFamily: 'Inter',
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                    color: AppColors.cyan,
                  ),
                ),
                const Spacer(),
                const LiveDot(),
                const SizedBox(width: 12),
                GestureDetector(
                  onTap: () => Navigator.pushNamed(ctx, '/alerts'),
                  child: Stack(
                    children: [
                      const Icon(
                        Icons.notifications_outlined,
                        color: AppColors.textSub,
                        size: 22,
                      ),
                      if (logs.alerts.isNotEmpty)
                        Positioned(
                          top: 0,
                          right: 0,
                          child: Container(
                            width: 8,
                            height: 8,
                            decoration: const BoxDecoration(
                              shape: BoxShape.circle,
                              color: AppColors.riskHigh,
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
              ],
            ),
          ),

          ServerStatusBanner(isUp: logs.serverUp),

          Expanded(
            child: RefreshIndicator(
              color: AppColors.cyan,
              backgroundColor: AppColors.surface1,
              onRefresh: () => ctx.read<LogsProvider>().refresh(),
              child: SingleChildScrollView(
                physics: const AlwaysScrollableScrollPhysics(),
                padding: const EdgeInsets.all(14),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Container(
                      padding: const EdgeInsets.all(13),
                      decoration: BoxDecoration(
                        color: AppColors.surface1,
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(
                          color: AppColors.cyan.withOpacity(0.28),
                        ),
                      ),
                      child: Row(
                        children: [
                          Image.asset(
                            'assets/images/fortismb_logo.png',
                            width: 48,
                            height: 48,
                            fit: BoxFit.contain,
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  'Welcome, ${auth.name}',
                                  style: const TextStyle(
                                    fontFamily: 'Inter',
                                    fontSize: 13,
                                    fontWeight: FontWeight.w700,
                                    color: AppColors.textPrimary,
                                  ),
                                ),
                                const Text(
                                  'Security Analyst  •  SOC Team',
                                  style: TextStyle(
                                    fontFamily: 'Inter',
                                    fontSize: 10,
                                    color: AppColors.textSub,
                                  ),
                                ),
                              ],
                            ),
                          ),
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 9,
                              vertical: 4,
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
                                fontSize: 8,
                                fontWeight: FontWeight.w700,
                                color: AppColors.cyan,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),

                    const SizedBox(height: 14),

                    Row(
                      children: [
                        Expanded(
                          child: KPICard(
                            value: '${stats['highRisk']}',
                            label: 'High Risk',
                            color: AppColors.riskHigh,
                            onTap: () => Navigator.pushNamed(ctx, '/alerts'),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: KPICard(
                            value: '${stats['totalLogs']}',
                            label: 'Total Logs',
                            color: AppColors.cyan,
                            onTap: () => Navigator.pushNamed(ctx, '/logs'),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: KPICard(
                            value: '${stats['normalLogs']}',
                            label: 'Normal',
                            color: AppColors.riskLow,
                            onTap: () {},
                          ),
                        ),
                      ],
                    ),

                    const SizedBox(height: 8),

                    Row(
                      children: [
                        Expanded(
                          child: KPICard(
                            value: '${stats['mediumRisk']}',
                            label: 'Med Risk',
                            color: AppColors.riskMedium,
                            onTap: () => Navigator.pushNamed(ctx, '/alerts'),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: KPICard(
                            value: '${stats['activeAlerts']}',
                            label: 'Active Alerts',
                            color: AppColors.purple,
                            onTap: () => Navigator.pushNamed(ctx, '/alerts'),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: KPICard(
                            value: stats['latestRisk'] as String? ?? '—',
                            label: 'Last Prediction',
                            color: AppColors.actionColor(
                              stats['latestAction'] as String?,
                            ),
                            onTap: () => Navigator.pushNamed(ctx, '/risk'),
                          ),
                        ),
                      ],
                    ),

                    const SizedBox(height: 14),

                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: AppColors.surface1,
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(color: AppColors.border),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            mainAxisAlignment:
                                MainAxisAlignment.spaceBetween,
                            children: [
                              const Text(
                                'Risk Activity',
                                style: TextStyle(
                                  fontFamily: 'Inter',
                                  fontSize: 11,
                                  fontWeight: FontWeight.w600,
                                  color: AppColors.textPrimary,
                                ),
                              ),
                              Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 7,
                                  vertical: 2,
                                ),
                                decoration: BoxDecoration(
                                  color: AppColors.riskHigh.withOpacity(0.12),
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: const Text(
                                  'Sysmon Feed',
                                  style: TextStyle(
                                    fontFamily: 'Inter',
                                    fontSize: 8,
                                    fontWeight: FontWeight.w600,
                                    color: AppColors.riskHigh,
                                  ),
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 10),
                          SizedBox(
                            height: 52,
                            child: Row(
                              crossAxisAlignment: CrossAxisAlignment.end,
                              children: _chartH.asMap().entries.map((e) {
                                return Expanded(
                                  child: Container(
                                    margin: const EdgeInsets.symmetric(
                                      horizontal: 0.5,
                                    ),
                                    height: e.value.toDouble(),
                                    decoration: BoxDecoration(
                                      color: e.key > 24
                                          ? AppColors.cyan.withOpacity(0.75)
                                          : AppColors.border.withOpacity(0.45),
                                      borderRadius: BorderRadius.circular(1.5),
                                    ),
                                  ),
                                );
                              }).toList(),
                            ),
                          ),
                          const SizedBox(height: 5),
                          const Row(
                            mainAxisAlignment:
                                MainAxisAlignment.spaceBetween,
                            children: [
                              Text(
                                'Earlier',
                                style: TextStyle(
                                  fontFamily: 'Inter',
                                  fontSize: 8,
                                  color: AppColors.textDim,
                                ),
                              ),
                              Text(
                                'Now',
                                style: TextStyle(
                                  fontFamily: 'Inter',
                                  fontSize: 8,
                                  fontWeight: FontWeight.w700,
                                  color: AppColors.cyan,
                                ),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),

                    const SizedBox(height: 16),

                    const Text(
                      'Quick Actions',
                      style: TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                        color: AppColors.textPrimary,
                      ),
                    ),

                    const SizedBox(height: 10),

                    Row(
                      children: [
                        Expanded(
                          child: QuickActionBtn(
                            label: 'Check\nLogs',
                            icon: Icons.list_alt_outlined,
                            color: AppColors.cyan,
                            onTap: () => Navigator.pushNamed(ctx, '/logs'),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: QuickActionBtn(
                            label: 'Alerts',
                            icon: Icons.notifications_outlined,
                            color: AppColors.riskHigh,
                            onTap: () => Navigator.pushNamed(ctx, '/alerts'),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: QuickActionBtn(
                            label: 'Risk\nAnalysis',
                            icon: Icons.radar_outlined,
                            color: AppColors.riskMedium,
                            onTap: () => Navigator.pushNamed(ctx, '/risk'),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: QuickActionBtn(
                            label: 'XAI\nExplain',
                            icon: Icons.auto_awesome_outlined,
                            color: AppColors.purple,
                            onTap: () => Navigator.pushNamed(ctx, '/xai'),
                          ),
                        ),
                      ],
                    ),

                    const SizedBox(height: 16),

                    if (stats['latestExplain'] != null &&
                        (stats['latestExplain'] as String).isNotEmpty) ...[
                      const Text(
                        'Latest AI Explanation',
                        style: TextStyle(
                          fontFamily: 'Inter',
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                          color: AppColors.textPrimary,
                        ),
                      ),
                      const SizedBox(height: 8),
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: AppColors.gold.withOpacity(0.07),
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(
                            color: AppColors.gold.withOpacity(0.3),
                          ),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Row(
                              children: [
                                Text(
                                  '✦ ',
                                  style: TextStyle(
                                    color: AppColors.gold,
                                    fontSize: 13,
                                  ),
                                ),
                                Text(
                                  'Gemini 2.0 Flash',
                                  style: TextStyle(
                                    fontFamily: 'Inter',
                                    fontSize: 10,
                                    fontWeight: FontWeight.w600,
                                    color: AppColors.gold,
                                  ),
                                ),
                              ],
                            ),
                            const SizedBox(height: 6),
                            Text(
                              stats['latestExplain'] as String,
                              style: const TextStyle(
                                fontFamily: 'Inter',
                                fontSize: 10,
                                color: AppColors.textSub,
                                height: 1.5,
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 14),
                    ],

                    SectionHeader(
                      title: 'Recent Sysmon Logs',
                      action: 'View all →',
                      onAction: () => Navigator.pushNamed(ctx, '/logs'),
                    ),

                    const SizedBox(height: 8),

                    if (recentLogs.isEmpty)
                      Container(
                        padding: const EdgeInsets.all(16),
                        decoration: BoxDecoration(
                          color: AppColors.surface1,
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: AppColors.border),
                        ),
                        child: const Column(
                          children: [
                            Icon(
                              Icons.radar_outlined,
                              color: AppColors.textDim,
                              size: 28,
                            ),
                            SizedBox(height: 6),
                            Text(
                              'No logs yet',
                              style: TextStyle(
                                fontFamily: 'Inter',
                                fontSize: 12,
                                color: AppColors.textMuted,
                              ),
                            ),
                            SizedBox(height: 4),
                            Text(
                              'Run sysmon_listener.py or submit a prediction',
                              style: TextStyle(
                                fontFamily: 'Inter',
                                fontSize: 9,
                                color: AppColors.textDim,
                              ),
                            ),
                          ],
                        ),
                      )
                    else
                      ...recentLogs.map(
                        (l) => SysmonLogRow(
                          log: l,
                          onTap: () => Navigator.pushNamed(ctx, '/alerts'),
                        ),
                      ),

                    const SizedBox(height: 8),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),

      bottomNavigationBar: FortiBottomNav(
        idx: _nav,
        onTap: (i) {
          setState(() => _nav = i);

          switch (i) {
            case 1:
              Navigator.pushNamed(ctx, '/logs');
              break;
            case 2:
              Navigator.pushNamed(ctx, '/alerts');
              break;
            case 3:
              Navigator.pushNamed(ctx, '/risk');
              break;
            case 4:
              Navigator.pushNamed(ctx, '/profile');
              break;
          }
        },
      ),
    );
  }
}