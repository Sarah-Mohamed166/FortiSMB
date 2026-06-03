import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../core/constants/app_colors.dart';
import '../../data/models/sysmon_log.dart';
import '../../data/repositories/app_provider.dart';
import '../widgets/shared_widgets.dart';

class AlertsScreen extends StatefulWidget {
  const AlertsScreen({super.key});

  @override
  State<AlertsScreen> createState() => _State();
}

class _State extends State<AlertsScreen> {
  int _nav = 2;
  String _filter = 'All';
  String _search = '';

  void _goBack(BuildContext ctx) {
    if (Navigator.canPop(ctx)) {
      Navigator.pop(ctx);
    } else {
      Navigator.pushReplacementNamed(ctx, '/dashboard');
    }
  }

  @override
  Widget build(BuildContext ctx) {
    final logs = ctx.watch<LogsProvider>();

    var alerts = logs.alerts;

    if (_filter == 'High Risk') {
      alerts = alerts.where((l) => l.isHighRisk).toList();
    }

    if (_filter == 'Medium Risk') {
      alerts = alerts.where((l) => l.isMediumRisk).toList();
    }

    if (_search.isNotEmpty) {
      final q = _search.toLowerCase();
      alerts = alerts
          .where(
            (l) =>
                l.role.toLowerCase().contains(q) ||
                l.action.toLowerCase().contains(q) ||
                l.finalRisk.toLowerCase().contains(q),
          )
          .toList();
    }

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
                  'Security Alerts',
                  style: TextStyle(
                    fontFamily: 'Inter',
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                    color: AppColors.textPrimary,
                  ),
                ),

                const Spacer(),

                if (logs.alerts.isNotEmpty)
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 3,
                    ),
                    decoration: BoxDecoration(
                      color: AppColors.riskHigh.withOpacity(0.13),
                      borderRadius: BorderRadius.circular(100),
                      border: Border.all(
                        color: AppColors.riskHigh.withOpacity(0.45),
                      ),
                    ),
                    child: Text(
                      '${logs.alerts.length} Active',
                      style: const TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 9,
                        fontWeight: FontWeight.w700,
                        color: AppColors.riskHigh,
                      ),
                    ),
                  ),
              ],
            ),
          ),

          ServerStatusBanner(isUp: logs.serverUp),

          Padding(
            padding: const EdgeInsets.fromLTRB(14, 10, 14, 0),
            child: Container(
              height: 36,
              decoration: BoxDecoration(
                color: AppColors.surface1,
                borderRadius: BorderRadius.circular(18),
                border: Border.all(color: AppColors.border),
              ),
              child: Row(
                children: [
                  const SizedBox(width: 12),
                  const Icon(
                    Icons.search,
                    color: AppColors.textDim,
                    size: 16,
                  ),
                  const SizedBox(width: 8),

                  Expanded(
                    child: TextField(
                      style: const TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 11,
                        color: AppColors.textPrimary,
                      ),
                      decoration: const InputDecoration(
                        hintText: 'Search alerts...',
                        hintStyle: TextStyle(
                          fontFamily: 'Inter',
                          fontSize: 10,
                          color: AppColors.textDim,
                        ),
                        border: InputBorder.none,
                        isDense: true,
                        contentPadding: EdgeInsets.zero,
                      ),
                      onChanged: (v) {
                        setState(() => _search = v);
                      },
                    ),
                  ),
                ],
              ),
            ),
          ),

          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            padding: const EdgeInsets.fromLTRB(14, 8, 14, 0),
            child: Row(
              children: [
                for (final f in ['All', 'High Risk', 'Medium Risk'])
                  Padding(
                    padding: const EdgeInsets.only(right: 7),
                    child: FortiChip(
                      label: f,
                      selected: _filter == f,
                      selectedColor: f == 'High Risk'
                          ? AppColors.riskHigh
                          : f == 'Medium Risk'
                              ? AppColors.riskMedium
                              : AppColors.cyan,
                      onTap: () {
                        setState(() => _filter = f);
                      },
                    ),
                  ),
              ],
            ),
          ),

          const SizedBox(height: 8),

          Expanded(
            child: RefreshIndicator(
              color: AppColors.cyan,
              backgroundColor: AppColors.surface1,
              onRefresh: () => ctx.read<LogsProvider>().refresh(),
              child: alerts.isEmpty
                  ? const Center(
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Text(
                            '🎉',
                            style: TextStyle(fontSize: 40),
                          ),
                          SizedBox(height: 12),
                          Text(
                            'No alerts',
                            style: TextStyle(
                              fontFamily: 'Inter',
                              fontSize: 13,
                              fontWeight: FontWeight.w600,
                              color: AppColors.textMuted,
                            ),
                          ),
                          SizedBox(height: 4),
                          Text(
                            'All Sysmon events are LOW risk',
                            style: TextStyle(
                              fontFamily: 'Inter',
                              fontSize: 11,
                              color: AppColors.textDim,
                            ),
                          ),
                        ],
                      ),
                    )
                  : ListView.builder(
                      padding: const EdgeInsets.symmetric(horizontal: 14),
                      itemCount: alerts.length,
                      itemBuilder: (_, i) => _alertCard(ctx, alerts[i]),
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

  Widget _alertCard(BuildContext ctx, SysmonLog log) {
    final c = AppColors.riskColor(log.finalRisk);

    return GestureDetector(
      onTap: () => Navigator.pushNamed(
        ctx,
        '/alert-detail',
        arguments: log,
      ),
      child: Container(
        margin: const EdgeInsets.only(bottom: 8),
        decoration: BoxDecoration(
          color: AppColors.surface1,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: log.isHighRisk ? c.withOpacity(0.4) : AppColors.border,
          ),
        ),
        child: Row(
          children: [
            Container(
              width: 3,
              height: 68,
              decoration: BoxDecoration(
                color: c.withOpacity(log.isHighRisk ? 0.85 : 0.45),
                borderRadius: const BorderRadius.only(
                  topLeft: Radius.circular(10),
                  bottomLeft: Radius.circular(10),
                ),
              ),
            ),

            const SizedBox(width: 10),

            Expanded(
              child: Padding(
                padding: const EdgeInsets.symmetric(vertical: 10),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        RiskBadge(level: log.finalRisk),
                        const SizedBox(width: 8),
                        StatusBadge(
                          text: log.systemAction,
                          color: AppColors.actionColor(log.systemAction),
                        ),
                      ],
                    ),

                    const SizedBox(height: 6),

                    Text(
                      log.aiQuery.length > 45
                          ? '${log.aiQuery.substring(0, 45)}...'
                          : log.aiQuery,
                      style: const TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                        color: AppColors.textPrimary,
                      ),
                    ),

                    const SizedBox(height: 3),

                    Text(
                      '${log.role}  •  ${log.action}  •  ${log.formattedTime}',
                      style: const TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 9,
                        color: AppColors.textSub,
                      ),
                    ),

                    if (log.isUsb)
                      const Text(
                        '🔌 USB involved',
                        style: TextStyle(
                          fontFamily: 'Inter',
                          fontSize: 8,
                          color: AppColors.riskHigh,
                        ),
                      ),

                    if (log.offHours)
                      const Text(
                        '🌙 Off-hours event',
                        style: TextStyle(
                          fontFamily: 'Inter',
                          fontSize: 8,
                          color: AppColors.riskMedium,
                        ),
                      ),
                  ],
                ),
              ),
            ),

            const Padding(
              padding: EdgeInsets.all(10),
              child: Icon(
                Icons.chevron_right,
                color: AppColors.textDim,
                size: 16,
              ),
            ),
          ],
        ),
      ),
    );
  }
}