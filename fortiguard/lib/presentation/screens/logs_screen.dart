import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../core/constants/app_colors.dart';
import '../../data/models/sysmon_log.dart';
import '../../data/repositories/app_provider.dart';
import '../widgets/shared_widgets.dart';

class LogsScreen extends StatefulWidget {
  const LogsScreen({super.key});

  @override
  State<LogsScreen> createState() => _State();
}

class _State extends State<LogsScreen> {
  int _nav = 1;
  String _filter = 'All';
  String _search = '';

  static const _filters = [
    'All',
    'Normal',
    'Medium Risk',
    'High Risk'
  ];

  Color _fc(String f) {
    switch (f) {
      case 'High Risk':
        return AppColors.riskHigh;
      case 'Medium Risk':
        return AppColors.riskMedium;
      case 'Normal':
        return AppColors.riskLow;
      default:
        return AppColors.cyan;
    }
  }

  void _goBack(BuildContext ctx) {
    if (Navigator.canPop(ctx)) {
      Navigator.pop(ctx);
    } else {
      Navigator.pushReplacementNamed(
        ctx,
        '/dashboard',
      );
    }
  }

  @override
  Widget build(BuildContext ctx) {
    final logs = ctx.watch<LogsProvider>();

    var list = logs.filtered(_filter);
    list = logs.search(list, _search);

    return Scaffold(
      backgroundColor: AppColors.bgPrimary,

      body: Column(
        children: [
          const FortiStatusBar(),

          /// HEADER
          Container(
            height: 52,
            color: AppColors.headerBg,
            padding: const EdgeInsets.symmetric(
              horizontal: 8,
            ),
            child: Row(
              children: [
                IconButton(
                  icon: const Icon(
                    Icons.arrow_back_ios_new,
                    size: 18,
                    color:
                        AppColors.textPrimary,
                  ),
                  onPressed: () =>
                      _goBack(ctx),
                ),

                const Text(
                  'Check Logs',
                  style: TextStyle(
                    fontFamily: 'Inter',
                    fontSize: 13,
                    fontWeight:
                        FontWeight.w600,
                    color:
                        AppColors.textPrimary,
                  ),
                ),

                const Spacer(),

                const LiveDot(),
              ],
            ),
          ),

          ServerStatusBanner(
            isUp: logs.serverUp,
          ),

          /// SEARCH
          Padding(
            padding:
                const EdgeInsets.fromLTRB(
              14,
              10,
              14,
              0,
            ),
            child: Container(
              height: 36,
              decoration: BoxDecoration(
                color: AppColors.surface1,
                borderRadius:
                    BorderRadius.circular(
                        18),
                border: Border.all(
                  color:
                      AppColors.border,
                ),
              ),
              child: Row(
                children: [
                  const SizedBox(
                      width: 12),
                  const Icon(
                    Icons.search,
                    color:
                        AppColors.textDim,
                    size: 16,
                  ),
                  const SizedBox(
                      width: 8),

                  Expanded(
                    child: TextField(
                      style:
                          const TextStyle(
                        fontFamily:
                            'Inter',
                        fontSize: 11,
                        color:
                            AppColors
                                .textPrimary,
                      ),
                      decoration:
                          const InputDecoration(
                        hintText:
                            'Search role, action, risk...',
                        hintStyle:
                            TextStyle(
                          fontFamily:
                              'Inter',
                          fontSize:
                              10,
                          color:
                              AppColors
                                  .textDim,
                        ),
                        border:
                            InputBorder
                                .none,
                        isDense:
                            true,
                        contentPadding:
                            EdgeInsets
                                .zero,
                      ),
                      onChanged: (v) {
                        setState(() {
                          _search = v;
                        });
                      },
                    ),
                  ),
                ],
              ),
            ),
          ),

          /// FILTERS
          SingleChildScrollView(
            scrollDirection:
                Axis.horizontal,
            padding:
                const EdgeInsets.fromLTRB(
              14,
              8,
              14,
              0,
            ),
            child: Row(
              children: _filters
                  .map(
                    (f) => Padding(
                      padding:
                          const EdgeInsets
                              .only(
                        right: 7,
                      ),
                      child:
                          FortiChip(
                        label: f,
                        selected:
                            _filter ==
                                f,
                        selectedColor:
                            _fc(f),
                        onTap: () {
                          setState(() {
                            _filter =
                                f;
                          });
                        },
                      ),
                    ),
                  )
                  .toList(),
            ),
          ),

          /// STATS
          Padding(
            padding:
                const EdgeInsets.fromLTRB(
              14,
              8,
              14,
              0,
            ),
            child: Row(
              children: [
                _stat(
                  '${logs.logs.length}',
                  'Total',
                  AppColors.cyan,
                ),
                const SizedBox(
                    width: 12),
                _stat(
                  '${logs.logs.where((l) => l.isHighRisk).length}',
                  'High',
                  AppColors.riskHigh,
                ),
                const SizedBox(
                    width: 12),
                _stat(
                  '${logs.logs.where((l) => l.isMediumRisk).length}',
                  'Medium',
                  AppColors.riskMedium,
                ),
                const SizedBox(
                    width: 12),
                _stat(
                  '${logs.logs.where((l) => !l.isAlert).length}',
                  'Normal',
                  AppColors.riskLow,
                ),
              ],
            ),
          ),

          const SizedBox(height: 8),

          if (logs.error != null)
            ErrorCard(
              message: logs.error!,
              onRetry: () => ctx
                  .read<
                      LogsProvider>()
                  .refresh(),
            ),

          /// LOG LIST
          Expanded(
            child:
                RefreshIndicator(
              color:
                  AppColors.cyan,
              backgroundColor:
                  AppColors
                      .surface1,
              onRefresh: () =>
                  ctx
                      .read<
                          LogsProvider>()
                      .refresh(),
              child: list
                      .isEmpty
                  ? Center(
                      child:
                          Column(
                        mainAxisSize:
                            MainAxisSize
                                .min,
                        children: [
                          const Text(
                            '🔍',
                            style:
                                TextStyle(
                              fontSize:
                                  40,
                            ),
                          ),
                          const SizedBox(
                              height:
                                  12),
                          const Text(
                            'No logs found',
                            style:
                                TextStyle(
                              fontFamily:
                                  'Inter',
                              fontSize:
                                  13,
                              fontWeight:
                                  FontWeight.w600,
                              color:
                                  AppColors.textMuted,
                            ),
                          ),
                        ],
                      ),
                    )
                  : ListView.builder(
                      padding:
                          const EdgeInsets
                              .symmetric(
                        horizontal:
                            14,
                      ),
                      itemCount:
                          list.length,
                      itemBuilder:
                          (_, i) =>
                              SysmonLogRow(
                        log:
                            list[i],
                        onTap:
                            () =>
                                _showDetail(
                          ctx,
                          list[i],
                        ),
                      ),
                    ),
            ),
          ),
        ],
      ),

      /// NAVIGATION
      bottomNavigationBar:
          FortiBottomNav(
        idx: _nav,
        onTap: (i) {
          if (i == _nav) {
            return;
          }

          setState(
              () => _nav = i);

          switch (i) {
            case 0:
              Navigator
                  .pushReplacementNamed(
                ctx,
                '/dashboard',
              );
              break;

            case 2:
              Navigator
                  .pushReplacementNamed(
                ctx,
                '/alerts',
              );
              break;

            case 3:
              Navigator
                  .pushReplacementNamed(
                ctx,
                '/risk',
              );
              break;

            case 4:
              Navigator
                  .pushReplacementNamed(
                ctx,
                '/profile',
              );
              break;
          }
        },
      ),
    );
  }

  Widget _stat(
    String v,
    String l,
    Color c,
  ) {
    return Row(
      children: [
        Container(
          width: 7,
          height: 7,
          decoration:
              BoxDecoration(
            shape:
                BoxShape.circle,
            color: c,
          ),
        ),
        const SizedBox(width: 4),
        Text(
          '$v $l',
          style:
              const TextStyle(
            fontFamily:
                'Inter',
            fontSize: 10,
            color:
                AppColors
                    .textSub,
          ),
        ),
      ],
    );
  }

  void _showDetail(
    BuildContext ctx,
    SysmonLog log,
  ) {
    showModalBottomSheet(
      context: ctx,
      builder: (_) => const SizedBox(),
    );
  }
}