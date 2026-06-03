import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../core/constants/app_colors.dart';
import '../../core/constants/api_constants.dart';
import '../../data/repositories/app_provider.dart';
import '../../data/models/prediction_response.dart';
import '../widgets/shared_widgets.dart';

class RiskAnalysisScreen extends StatefulWidget {
  const RiskAnalysisScreen({super.key});

  @override
  State<RiskAnalysisScreen> createState() => _State();
}

class _State extends State<RiskAnalysisScreen> {
  int _nav = 3;

  String _action = 'logon';
  String _role = FortiSMBRoles.adminEmployee;
  String _fileOp = 'copy';
  bool _isUsb = false;
  bool _offHours = false;
  double _hour = 14;
  String _aiQuery = 'Sysmon Event detected by FortiSMB mobile';
  bool _loading = false;

  void _goBack(BuildContext ctx) {
    if (Navigator.canPop(ctx)) {
      Navigator.pop(ctx);
    } else {
      Navigator.pushReplacementNamed(ctx, '/dashboard');
    }
  }

  Future<void> _runPrediction() async {
    setState(() => _loading = true);

    final pred = context.read<PredictionProvider>();

    await pred.predict(
      aiQuery: _aiQuery,
      action: _action,
      role: _role,
      fileOp: _fileOp,
      isUsb: _isUsb,
      hour: _hour,
      offHours: _offHours,
      date: DateTime.now().toIso8601String().substring(0, 10),
    );

    setState(() => _loading = false);

    context.read<LogsProvider>().refresh();
  }

  @override
  Widget build(BuildContext ctx) {
    final pred = ctx.watch<PredictionProvider>();
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
                  'Risk Analysis',
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
                    color: AppColors.cyan.withOpacity(0.10),
                    borderRadius: BorderRadius.circular(100),
                    border: Border.all(
                      color: AppColors.cyan.withOpacity(0.3),
                    ),
                  ),
                  child: const Text(
                    'POST /predict',
                    style: TextStyle(
                      fontFamily: 'Inter',
                      fontSize: 8,
                      fontWeight: FontWeight.w600,
                      color: AppColors.cyan,
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
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: AppColors.cyan.withOpacity(0.06),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(
                        color: AppColors.cyan.withOpacity(0.25),
                      ),
                    ),
                    child: const Text(
                      'Submit a real event to FortiSMB AI (M1 Random Forest → M2 XGBoost → Gemini 2.0 Flash). Fields match your QueryRequest exactly.',
                      style: TextStyle(
                        fontFamily: 'Inter',
                        fontSize: 9,
                        color: AppColors.textSub,
                        height: 1.5,
                      ),
                    ),
                  ),

                  const SizedBox(height: 14),

                  _lbl('AI QUERY'),
                  const SizedBox(height: 5),

                  TextFormField(
                    style: const TextStyle(
                      fontFamily: 'Inter',
                      fontSize: 11,
                      color: AppColors.textPrimary,
                    ),
                    initialValue: _aiQuery,
                    decoration: _dec('Describe the event...'),
                    onChanged: (v) => setState(() => _aiQuery = v),
                  ),

                  const SizedBox(height: 12),

                  _lbl('ACTION  (logon | file | device)'),
                  const SizedBox(height: 5),

                  Row(
                    children: [
                      for (final a in ['logon', 'file', 'device']) ...[
                        GestureDetector(
                          onTap: () => setState(() => _action = a),
                          child: Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 12,
                              vertical: 7,
                            ),
                            decoration: BoxDecoration(
                              color: _action == a
                                  ? AppColors.cyan.withOpacity(0.12)
                                  : AppColors.surface1,
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(
                                color: _action == a
                                    ? AppColors.cyan.withOpacity(0.5)
                                    : AppColors.border,
                              ),
                            ),
                            child: Text(
                              a,
                              style: TextStyle(
                                fontFamily: 'Inter',
                                fontSize: 10,
                                fontWeight: _action == a
                                    ? FontWeight.w600
                                    : FontWeight.w400,
                                color: _action == a
                                    ? AppColors.cyan
                                    : AppColors.textMuted,
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                      ],
                    ],
                  ),

                  const SizedBox(height: 12),

                  _lbl('FORTISMB ROLE'),
                  const SizedBox(height: 5),

                  Container(
                    decoration: BoxDecoration(
                      color: AppColors.surface1,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(
                        color: AppColors.cyan.withOpacity(0.4),
                        width: 1.5,
                      ),
                    ),
                    child: DropdownButtonHideUnderline(
                      child: DropdownButton<String>(
                        value: _role,
                        isExpanded: true,
                        padding: const EdgeInsets.symmetric(horizontal: 12),
                        dropdownColor: AppColors.surface1,
                        style: const TextStyle(
                          fontFamily: 'Inter',
                          fontSize: 11,
                          color: AppColors.cyan,
                        ),
                        icon: const Icon(
                          Icons.keyboard_arrow_down,
                          color: AppColors.textMuted,
                          size: 16,
                        ),
                        items: FortiSMBRoles.all
                            .map(
                              (r) => DropdownMenuItem(
                                value: r,
                                child: Text(
                                  r,
                                  style: const TextStyle(
                                    fontFamily: 'Inter',
                                    fontSize: 11,
                                    color: AppColors.cyan,
                                  ),
                                ),
                              ),
                            )
                            .toList(),
                        onChanged: (v) {
                          if (v != null) setState(() => _role = v);
                        },
                      ),
                    ),
                  ),

                  const SizedBox(height: 12),

                  _lbl('FILE OPERATION'),
                  const SizedBox(height: 5),

                  Row(
                    children: [
                      for (final f in ['copy', 'read', 'write', 'delete']) ...[
                        GestureDetector(
                          onTap: () => setState(() => _fileOp = f),
                          child: Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 10,
                              vertical: 6,
                            ),
                            decoration: BoxDecoration(
                              color: _fileOp == f
                                  ? AppColors.riskMedium.withOpacity(0.12)
                                  : AppColors.surface1,
                              borderRadius: BorderRadius.circular(7),
                              border: Border.all(
                                color: _fileOp == f
                                    ? AppColors.riskMedium.withOpacity(0.5)
                                    : AppColors.border,
                              ),
                            ),
                            child: Text(
                              f,
                              style: TextStyle(
                                fontFamily: 'Inter',
                                fontSize: 9,
                                fontWeight: _fileOp == f
                                    ? FontWeight.w600
                                    : FontWeight.w400,
                                color: _fileOp == f
                                    ? AppColors.riskMedium
                                    : AppColors.textMuted,
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 6),
                      ],
                    ],
                  ),

                  const SizedBox(height: 12),

                  Row(
                    children: [
                      Expanded(
                        child: GestureDetector(
                          onTap: () => setState(() => _isUsb = !_isUsb),
                          child: _toggleBox(
                            title: 'IS USB',
                            value: _isUsb ? 'ON ⚠' : 'OFF',
                            active: _isUsb,
                            color: AppColors.riskHigh,
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: GestureDetector(
                          onTap: () => setState(() => _offHours = !_offHours),
                          child: _toggleBox(
                            title: 'OFF HOURS',
                            value: _offHours ? 'ON 🌙' : 'OFF',
                            active: _offHours,
                            color: AppColors.riskMedium,
                          ),
                        ),
                      ),
                    ],
                  ),

                  const SizedBox(height: 12),

                  _lbl('HOUR: ${_hour.toInt()}:00'),
                  const SizedBox(height: 4),

                  Slider(
                    value: _hour,
                    min: 0,
                    max: 23,
                    divisions: 23,
                    activeColor: _hour > 18 || _hour < 8
                        ? AppColors.riskHigh
                        : AppColors.cyan,
                    inactiveColor: AppColors.border.withOpacity(0.5),
                    onChanged: (v) => setState(() => _hour = v),
                  ),

                  const SizedBox(height: 18),

                  if (pred.error != null) ...[
                    ErrorCard(
                      message: pred.error!,
                      onRetry: _runPrediction,
                    ),
                    const SizedBox(height: 12),
                  ],

                  SizedBox(
                    width: double.infinity,
                    height: 48,
                    child: ElevatedButton(
                      onPressed: (_loading || pred.loading)
                          ? null
                          : _runPrediction,
                      child: _loading || pred.loading
                          ? const Text('Analysing...')
                          : const Text('🤖 Analyse with FortiSMB AI'),
                    ),
                  ),

                  if (pred.response != null) ...[
                    const SizedBox(height: 20),
                    _ResultPanel(resp: pred.response!),
                  ],

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
            case 4:
              Navigator.pushReplacementNamed(ctx, '/profile');
              break;
          }
        },
      ),
    );
  }

  Widget _toggleBox({
    required String title,
    required String value,
    required bool active,
    required Color color,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
      decoration: BoxDecoration(
        color: active ? color.withOpacity(0.08) : AppColors.surface1,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: active ? color.withOpacity(0.4) : AppColors.border,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: const TextStyle(fontSize: 8)),
          const SizedBox(height: 3),
          Text(
            value,
            style: TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w700,
              color: active ? color : AppColors.textMuted,
            ),
          ),
        ],
      ),
    );
  }

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

  InputDecoration _dec(String h) => InputDecoration(hintText: h);
}

class _ResultPanel extends StatelessWidget {
  final PredictionResponse resp;

  const _ResultPanel({required this.resp});

  @override
  Widget build(BuildContext ctx) {
    final c = AppColors.riskColor(resp.finalRisk);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('Prediction Result'),
        const SizedBox(height: 10),
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: c.withOpacity(0.08),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: c.withOpacity(0.5), width: 1.5),
          ),
          child: Text(
            resp.finalRisk.toUpperCase(),
            style: TextStyle(
              fontSize: 28,
              fontWeight: FontWeight.w800,
              color: c,
            ),
          ),
        ),
      ],
    );
  }
}