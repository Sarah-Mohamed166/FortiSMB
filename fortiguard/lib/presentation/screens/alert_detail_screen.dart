import 'package:flutter/material.dart';
import '../../core/constants/app_colors.dart';
import '../../data/models/sysmon_log.dart';
import '../widgets/shared_widgets.dart';

class AlertDetailScreen extends StatelessWidget {
  const AlertDetailScreen({super.key});

  void _goBack(BuildContext ctx) {
    if (Navigator.canPop(ctx)) {
      Navigator.pop(ctx);
    } else {
      Navigator.pushReplacementNamed(ctx, '/dashboard');
    }
  }

  @override
  Widget build(BuildContext ctx) {
    final log = ModalRoute.of(ctx)!.settings.arguments as SysmonLog;
    final c = AppColors.riskColor(log.finalRisk);

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
                  'Alert Investigation',
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

          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(14),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: c.withOpacity(0.07),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(
                        color: c.withOpacity(0.45),
                        width: 1.5,
                      ),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'SYSMON ALERT • ${log.eventIdLabel}',
                          style: TextStyle(
                            fontFamily: 'Inter',
                            fontSize: 9,
                            fontWeight: FontWeight.w700,
                            color: c,
                          ),
                        ),
                        const SizedBox(height: 6),
                        Text(
                          log.aiQuery,
                          style: const TextStyle(
                            fontFamily: 'Inter',
                            fontSize: 14,
                            fontWeight: FontWeight.w700,
                            color: AppColors.textPrimary,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Row(
                          children: [
                            RiskBadge(level: log.finalRisk),
                            const SizedBox(width: 8),
                            StatusBadge(
                              text: 'ACTIVE',
                              color: AppColors.riskMedium,
                            ),
                            const SizedBox(width: 8),
                            StatusBadge(
                              text: log.systemAction,
                              color: AppColors.actionColor(log.systemAction),
                            ),
                          ],
                        ),
                      ],
                    ),
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
                      children: [
                        _row('Role', log.role, AppColors.textPrimary),
                        _row('Action', log.action, AppColors.textPrimary),
                        _row(
                          'File Operation',
                          log.fileOp.isEmpty ? '—' : log.fileOp,
                          AppColors.textPrimary,
                        ),
                        _row(
                          'USB Involved',
                          log.isUsb ? 'Yes ⚠' : 'No',
                          log.isUsb ? AppColors.riskHigh : AppColors.riskLow,
                        ),
                        _row(
                          'Hour',
                          '${log.hour.toInt()}:00${log.offHours ? " (Off-Hours 🌙)" : ""}',
                          log.offHours
                              ? AppColors.riskMedium
                              : AppColors.textPrimary,
                        ),
                        _row(
                          'Timestamp',
                          log.formattedTime,
                          AppColors.textSub,
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 14),

                  const Text(
                    'AI Explanation',
                    style: TextStyle(
                      fontFamily: 'Inter',
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                      color: AppColors.textPrimary,
                    ),
                  ),

                  const SizedBox(height: 8),

                  Container(
                    padding: const EdgeInsets.all(14),
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
                              'Gemini 2.0 Flash (LLMService)',
                              style: TextStyle(
                                fontFamily: 'Inter',
                                fontSize: 10,
                                fontWeight: FontWeight.w600,
                                color: AppColors.gold,
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Text(
                          log.explanation.isNotEmpty
                              ? log.explanation
                              : 'No explanation returned from backend.',
                          style: const TextStyle(
                            fontFamily: 'Inter',
                            fontSize: 11,
                            color: AppColors.textSub,
                            height: 1.6,
                          ),
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 14),

                  Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: AppColors.actionColor(log.systemAction)
                          .withOpacity(0.08),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(
                        color: AppColors.actionColor(log.systemAction)
                            .withOpacity(0.4),
                      ),
                    ),
                    child: Row(
                      children: [
                        Icon(
                          log.finalRisk == 'High'
                              ? Icons.block
                              : log.finalRisk == 'Medium'
                                  ? Icons.notification_important_outlined
                                  : Icons.monitor_heart_outlined,
                          color: AppColors.actionColor(log.systemAction),
                          size: 24,
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                'System Action',
                                style: TextStyle(
                                  fontFamily: 'Inter',
                                  fontSize: 10,
                                  color: AppColors.actionColor(log.systemAction)
                                      .withOpacity(0.7),
                                ),
                              ),
                              Text(
                                log.systemAction,
                                style: TextStyle(
                                  fontFamily: 'Inter',
                                  fontSize: 14,
                                  fontWeight: FontWeight.w800,
                                  color:
                                      AppColors.actionColor(log.systemAction),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 14),

                  Row(
                    children: [
                      Expanded(
                        child: GestureDetector(
                          onTap: () => Navigator.pushNamed(ctx, '/xai'),
                          child: _actionButton(
                            'View XAI',
                            AppColors.purple,
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: GestureDetector(
                          onTap: () => Navigator.pushNamed(ctx, '/risk'),
                          child: _actionButton(
                            'Risk Analysis',
                            AppColors.riskMedium,
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: GestureDetector(
                          onTap: () => _goBack(ctx),
                          child: _actionButton(
                            'Close',
                            AppColors.textMuted,
                          ),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _actionButton(String text, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 12),
      decoration: BoxDecoration(
        color: color.withOpacity(0.09),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withOpacity(0.4)),
      ),
      child: Center(
        child: Text(
          text,
          style: TextStyle(
            fontFamily: 'Inter',
            fontSize: 10,
            fontWeight: FontWeight.w600,
            color: color,
          ),
        ),
      ),
    );
  }

  Widget _row(String k, String v, Color vc) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        children: [
          SizedBox(
            width: 100,
            child: Text(
              k,
              style: const TextStyle(
                fontFamily: 'Inter',
                fontSize: 10,
                color: AppColors.textDim,
              ),
            ),
          ),
          Expanded(
            child: Text(
              v,
              style: TextStyle(
                fontFamily: 'Inter',
                fontSize: 10,
                fontWeight: FontWeight.w600,
                color: vc,
              ),
            ),
          ),
        ],
      ),
    );
  }
}