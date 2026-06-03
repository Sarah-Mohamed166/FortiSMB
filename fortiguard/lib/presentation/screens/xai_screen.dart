import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../core/constants/app_colors.dart';
import '../../data/repositories/app_provider.dart';
import '../../data/models/xai_model.dart';
import '../widgets/shared_widgets.dart';

class XAIScreen extends StatefulWidget {
  const XAIScreen({super.key});

  @override
  State<XAIScreen> createState() => _State();
}

class _State extends State<XAIScreen> {
  int _nav = 3;

  void _goBack(BuildContext ctx) {
    if (Navigator.canPop(ctx)) {
      Navigator.pop(ctx);
    } else {
      Navigator.pushReplacementNamed(ctx, '/dashboard');
    }
  }

  @override
  Widget build(BuildContext ctx) {
    final pred = ctx.watch<PredictionProvider>();
    final logs = ctx.watch<LogsProvider>();
    final xai = pred.xai;

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
                  'XAI Explanation',
                  style: TextStyle(
                    fontFamily: 'Inter',
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                    color: AppColors.textPrimary,
                  ),
                ),

                const Spacer(),

                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 8,
                    vertical: 3,
                  ),
                  decoration: BoxDecoration(
                    color: AppColors.purple.withOpacity(0.13),
                    borderRadius: BorderRadius.circular(100),
                    border: Border.all(
                      color: AppColors.purple.withOpacity(0.4),
                    ),
                  ),
                  child: const Text(
                    '✦ Gemini 2.0',
                    style: TextStyle(
                      fontFamily: 'Inter',
                      fontSize: 8,
                      fontWeight: FontWeight.w600,
                      color: AppColors.purple,
                    ),
                  ),
                ),
              ],
            ),
          ),

          ServerStatusBanner(isUp: logs.serverUp),

          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(14),
              child: xai == null
                  ? _noXAI(ctx)
                  : _xaiContent(ctx, xai),
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
            case 4:
              Navigator.pushReplacementNamed(ctx, '/profile');
              break;
          }
        },
      ),
    );
  }

  Widget _noXAI(BuildContext ctx) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: AppColors.surface1,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: AppColors.border),
          ),
          child: const Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'No explanation yet',
                style: TextStyle(
                  fontFamily: 'Inter',
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                  color: AppColors.textMuted,
                ),
              ),
              SizedBox(height: 6),
              Text(
                'No explanation returned from backend.\n\n'
                'To generate a real explanation:\n'
                '1. Go to Risk Analysis\n'
                '2. Submit an event to POST /predict\n'
                '3. Gemini 2.0 Flash will explain the result here.',
                style: TextStyle(
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

        SizedBox(
          width: double.infinity,
          height: 44,
          child: ElevatedButton(
            onPressed: () => Navigator.pushReplacementNamed(ctx, '/risk'),
            child: const Text('Go to Risk Analysis →'),
          ),
        ),
      ],
    );
  }

  Widget _xaiContent(
    BuildContext ctx,
    XAIExplanationModel xai,
  ) {
    final c = AppColors.riskColor(xai.finalRisk);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: c.withOpacity(0.07),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(
              color: c.withOpacity(0.35),
              width: 1.5,
            ),
          ),
          child: Row(
            children: [
              Icon(
                xai.finalRisk == 'High'
                    ? Icons.block
                    : Icons.notification_important_outlined,
                color: AppColors.actionColor(xai.systemAction),
                size: 22,
              ),

              const SizedBox(width: 10),

              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Recommended Action',
                      style: TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 9,
                        color: AppColors.textMuted,
                      ),
                    ),
                    Text(
                      xai.systemAction,
                      style: TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 13,
                        fontWeight: FontWeight.w800,
                        color: AppColors.actionColor(xai.systemAction),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),

        const SizedBox(height: 10),
      ],
    );
  }
}