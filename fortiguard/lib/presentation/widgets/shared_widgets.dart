import 'package:flutter/material.dart';
import '../../core/constants/app_colors.dart';
import '../../data/models/sysmon_log.dart';

// ── Status bar ─────────────────────────────────────────────────
class FortiStatusBar extends StatelessWidget {
  const FortiStatusBar({super.key});
  @override
  Widget build(BuildContext context) => Container(
    height:32, color:AppColors.surface2,
    padding:const EdgeInsets.symmetric(horizontal:14),
    child:const Row(children:[
      Text('9:41',style:TextStyle(fontFamily:'Inter',fontSize:9,fontWeight:FontWeight.w500,color:AppColors.textPrimary)),
      Spacer(),
      Text('●●● WiFi 🔋',style:TextStyle(fontFamily:'Inter',fontSize:9,color:AppColors.textMuted)),
    ]),
  );
}

// ── Grid background ────────────────────────────────────────────
class GridPainter extends CustomPainter {
  @override void paint(Canvas c,Size s){
    final p=Paint()..color=AppColors.border.withOpacity(0.06)..strokeWidth=1;
    for(double y=0;y<s.height;y+=60)c.drawLine(Offset(0,y),Offset(s.width,y),p);
    for(double x=0;x<s.width;x+=80)c.drawLine(Offset(x,0),Offset(x,s.height),p);
  }
  @override bool shouldRepaint(_)=>false;
}

// ── Glow orb ───────────────────────────────────────────────────
class GlowOrb extends StatelessWidget {
  final Color color;final double size,opacity;
  const GlowOrb({super.key,required this.color,this.size=260,this.opacity=0.07});
  @override Widget build(BuildContext context)=>Container(width:size,height:size,
    decoration:BoxDecoration(shape:BoxShape.circle,gradient:RadialGradient(colors:[color.withOpacity(opacity),Colors.transparent])));
}

// ── Animated live dot ──────────────────────────────────────────
class LiveDot extends StatefulWidget{const LiveDot({super.key});@override State<LiveDot> createState()=>_LiveDotState();}
class _LiveDotState extends State<LiveDot> with SingleTickerProviderStateMixin{
  late AnimationController _c;
  @override void initState(){super.initState();_c=AnimationController(vsync:this,duration:const Duration(seconds:1))..repeat(reverse:true);}
  @override void dispose(){_c.dispose();super.dispose();}
  @override Widget build(BuildContext ctx)=>Row(mainAxisSize:MainAxisSize.min,children:[
    FadeTransition(opacity:_c,child:Container(width:6,height:6,decoration:const BoxDecoration(shape:BoxShape.circle,color:AppColors.riskLow))),
    const SizedBox(width:5),
    const Text('LIVE',style:TextStyle(fontFamily:'Inter',fontSize:8,fontWeight:FontWeight.w700,color:AppColors.riskLow,letterSpacing:0.6)),
  ]);
}

// ── FortiCard ──────────────────────────────────────────────────
class FortiCard extends StatelessWidget{
  final Widget child;final Color? borderColor,bg;
  final EdgeInsetsGeometry? padding;final VoidCallback? onTap;final double radius;
  const FortiCard({super.key,required this.child,this.borderColor,this.bg,this.padding,this.onTap,this.radius=10});
  @override Widget build(BuildContext ctx)=>GestureDetector(onTap:onTap,child:Container(
    padding:padding??const EdgeInsets.all(14),
    decoration:BoxDecoration(color:bg??AppColors.surface1,borderRadius:BorderRadius.circular(radius),
      border:Border.all(color:borderColor??AppColors.border)),
    child:child));
}

// ── Risk badge ─────────────────────────────────────────────────
class RiskBadge extends StatelessWidget{
  final String level;const RiskBadge({super.key,required this.level});
  @override Widget build(BuildContext ctx){
    final c=AppColors.riskColor(level);
    return Container(padding:const EdgeInsets.symmetric(horizontal:8,vertical:3),
      decoration:BoxDecoration(color:c.withOpacity(0.13),borderRadius:BorderRadius.circular(100),border:Border.all(color:c.withOpacity(0.45))),
      child:Row(mainAxisSize:MainAxisSize.min,children:[
        Container(width:5,height:5,decoration:BoxDecoration(shape:BoxShape.circle,color:c)),
        const SizedBox(width:4),
        Text(level.toUpperCase(),style:TextStyle(fontFamily:'Inter',fontSize:8,fontWeight:FontWeight.w700,color:c)),
      ]));
  }
}

// ── Status badge ───────────────────────────────────────────────
class StatusBadge extends StatelessWidget{
  final String text;final Color color;
  const StatusBadge({super.key,required this.text,required this.color});
  @override Widget build(BuildContext ctx)=>Container(
    padding:const EdgeInsets.symmetric(horizontal:8,vertical:3),
    decoration:BoxDecoration(color:color.withOpacity(0.12),borderRadius:BorderRadius.circular(4),border:Border.all(color:color.withOpacity(0.4))),
    child:Text(text,style:TextStyle(fontFamily:'Inter',fontSize:9,fontWeight:FontWeight.w700,color:color)));
}

// ── KPI card ───────────────────────────────────────────────────
class KPICard extends StatelessWidget{
  final String value,label;final Color color;final VoidCallback? onTap;
  const KPICard({super.key,required this.value,required this.label,required this.color,this.onTap});
  @override Widget build(BuildContext ctx)=>GestureDetector(onTap:onTap,child:Container(
    padding:const EdgeInsets.all(12),
    decoration:BoxDecoration(color:color.withOpacity(0.09),borderRadius:BorderRadius.circular(10),border:Border.all(color:color.withOpacity(0.35))),
    child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
      Text(value,style:TextStyle(fontFamily:'Inter',fontSize:20,fontWeight:FontWeight.w800,color:color)),
      const SizedBox(height:3),
      Text(label,style:const TextStyle(fontFamily:'Inter',fontSize:9,color:AppColors.textSub)),
    ])));
}

// ── Quick action button ────────────────────────────────────────
class QuickActionBtn extends StatelessWidget{
  final String label;final IconData icon;final Color color;final VoidCallback? onTap;
  const QuickActionBtn({super.key,required this.label,required this.icon,required this.color,this.onTap});
  @override Widget build(BuildContext ctx)=>GestureDetector(onTap:onTap,child:Container(
    padding:const EdgeInsets.symmetric(vertical:14,horizontal:8),
    decoration:BoxDecoration(color:color.withOpacity(0.09),borderRadius:BorderRadius.circular(10),border:Border.all(color:color.withOpacity(0.3))),
    child:Column(mainAxisSize:MainAxisSize.min,children:[
      Container(width:38,height:38,decoration:BoxDecoration(shape:BoxShape.circle,color:color.withOpacity(0.12)),
        child:Icon(icon,color:color,size:19)),
      const SizedBox(height:7),
      Text(label,style:TextStyle(fontFamily:'Inter',fontSize:10,fontWeight:FontWeight.w600,color:color),textAlign:TextAlign.center),
    ])));
}

// ── Section header ─────────────────────────────────────────────
class SectionHeader extends StatelessWidget{
  final String title;final String? action;final VoidCallback? onAction;
  const SectionHeader({super.key,required this.title,this.action,this.onAction});
  @override Widget build(BuildContext ctx)=>Row(mainAxisAlignment:MainAxisAlignment.spaceBetween,children:[
    Text(title,style:const TextStyle(fontFamily:'Inter',fontSize:13,fontWeight:FontWeight.w600,color:AppColors.textPrimary)),
    if(action!=null)GestureDetector(onTap:onAction,child:Text(action!,style:const TextStyle(fontFamily:'Inter',fontSize:10,color:AppColors.cyan))),
  ]);
}

// ── Sysmon log row ─────────────────────────────────────────────
class SysmonLogRow extends StatelessWidget{
  final SysmonLog log;final VoidCallback? onTap;
  const SysmonLogRow({super.key,required this.log,this.onTap});
  @override Widget build(BuildContext ctx){
    final c=AppColors.riskColor(log.finalRisk);
    return GestureDetector(onTap:onTap,child:Container(
      margin:const EdgeInsets.only(bottom:7),
      decoration:BoxDecoration(color:AppColors.surface1,borderRadius:BorderRadius.circular(10),
        border:Border.all(color:log.isHighRisk?c.withOpacity(0.35):AppColors.border)),
      child:Row(children:[
        Container(width:3,height:60,decoration:BoxDecoration(color:c.withOpacity(log.isHighRisk?0.85:0.4),
          borderRadius:const BorderRadius.only(topLeft:Radius.circular(10),bottomLeft:Radius.circular(10)))),
        const SizedBox(width:10),
        Container(width:28,height:28,decoration:BoxDecoration(shape:BoxShape.circle,color:c.withOpacity(0.12),border:Border.all(color:c.withOpacity(0.4))),
          child:Center(child:Text(log.eventIdLabel.substring(0,2),style:TextStyle(fontFamily:'Inter',fontSize:7,fontWeight:FontWeight.w700,color:c)))),
        const SizedBox(width:9),
        Expanded(child:Padding(padding:const EdgeInsets.symmetric(vertical:9),child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
          Text(log.aiQuery.length>40?log.aiQuery.substring(0,40)+'...':log.aiQuery,style:const TextStyle(fontFamily:'Inter',fontSize:11,fontWeight:FontWeight.w600,color:AppColors.textPrimary)),
          const SizedBox(height:2),
          Text('${log.role}  •  ${log.action}  •  ${log.fileOp}',style:const TextStyle(fontFamily:'Inter',fontSize:9,color:AppColors.textSub)),
          const SizedBox(height:3),
          Row(children:[
            Container(padding:const EdgeInsets.symmetric(horizontal:5,vertical:1),
              decoration:BoxDecoration(color:AppColors.actionColor(log.systemAction).withOpacity(0.12),borderRadius:BorderRadius.circular(3)),
              child:Text(log.systemAction,style:TextStyle(fontFamily:'Inter',fontSize:7,fontWeight:FontWeight.w700,color:AppColors.actionColor(log.systemAction)))),
            const SizedBox(width:6),
            Text(log.formattedTime,style:const TextStyle(fontFamily:'Inter',fontSize:8,color:AppColors.textDim)),
          ]),
        ]))),
        Padding(padding:const EdgeInsets.all(10),child:Column(crossAxisAlignment:CrossAxisAlignment.end,children:[
          RiskBadge(level:log.finalRisk),
          const SizedBox(height:4),
          if(log.isUsb)const Text('🔌 USB',style:TextStyle(fontFamily:'Inter',fontSize:7,color:AppColors.riskHigh)),
          if(log.offHours)const Text('🌙 Off-hrs',style:TextStyle(fontFamily:'Inter',fontSize:7,color:AppColors.riskMedium)),
        ])),
      ]),
    ));
  }
}

// ── FortiChip ──────────────────────────────────────────────────
class FortiChip extends StatelessWidget{
  final String label;final bool selected;final Color? selectedColor;final VoidCallback? onTap;
  const FortiChip({super.key,required this.label,this.selected=false,this.selectedColor,this.onTap});
  @override Widget build(BuildContext ctx){
    final c=selectedColor??AppColors.cyan;
    return GestureDetector(onTap:onTap,child:Container(
      padding:const EdgeInsets.symmetric(horizontal:12,vertical:5),
      decoration:BoxDecoration(color:selected?c.withOpacity(0.13):AppColors.surface1,borderRadius:BorderRadius.circular(100),border:Border.all(color:selected?c.withOpacity(0.5):AppColors.border)),
      child:Text(label,style:TextStyle(fontFamily:'Inter',fontSize:10,fontWeight:selected?FontWeight.w600:FontWeight.w400,color:selected?c:AppColors.textMuted))));
  }
}

// ── Bottom nav ─────────────────────────────────────────────────
const _saNavItems=[
  _N(Icons.shield_outlined,'Home'),
  _N(Icons.list_alt_outlined,'Logs'),
  _N(Icons.notifications_outlined,'Alerts'),
  _N(Icons.radar_outlined,'Risk'),
  _N(Icons.person_outline,'Profile'),
];
class _N{final IconData i;final String l;const _N(this.i,this.l);}

class FortiBottomNav extends StatelessWidget{
  final int idx;final ValueChanged<int> onTap;
  const FortiBottomNav({super.key,required this.idx,required this.onTap});
  @override Widget build(BuildContext ctx)=>Container(
    decoration:const BoxDecoration(color:AppColors.surface2,border:Border(top:BorderSide(color:AppColors.border))),
    child:SafeArea(child:SizedBox(height:54,child:Row(
      children:List.generate(_saNavItems.length,(i){
        final sel=i==idx;final c=sel?AppColors.cyan:AppColors.textDim;
        return Expanded(child:GestureDetector(onTap:()=>onTap(i),behavior:HitTestBehavior.opaque,
          child:Column(mainAxisAlignment:MainAxisAlignment.center,children:[
            if(sel)Container(width:28,height:2,margin:const EdgeInsets.only(bottom:3),decoration:BoxDecoration(color:AppColors.cyan,borderRadius:BorderRadius.circular(1))),
            Icon(_saNavItems[i].i,color:c,size:sel?21:19),
            const SizedBox(height:2),
            Text(_saNavItems[i].l,style:TextStyle(fontFamily:'Inter',fontSize:9,fontWeight:sel?FontWeight.w600:FontWeight.w400,color:c)),
          ])));
      }),
    ))));
}

// ── Error card ─────────────────────────────────────────────────
class ErrorCard extends StatelessWidget{
  final String message;final VoidCallback? onRetry;
  const ErrorCard({super.key,required this.message,this.onRetry});
  @override Widget build(BuildContext ctx)=>Container(
    margin:const EdgeInsets.all(14),padding:const EdgeInsets.all(14),
    decoration:BoxDecoration(color:AppColors.riskHigh.withOpacity(0.08),borderRadius:BorderRadius.circular(10),border:Border.all(color:AppColors.riskHigh.withOpacity(0.35))),
    child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
      const Text('⚠  Connection Error',style:TextStyle(fontFamily:'Inter',fontSize:12,fontWeight:FontWeight.w700,color:AppColors.riskHigh)),
      const SizedBox(height:6),
      Text(message,style:const TextStyle(fontFamily:'Inter',fontSize:11,color:AppColors.textSub,height:1.5)),
      if(onRetry!=null)...[const SizedBox(height:12),
        GestureDetector(onTap:onRetry,child:Container(padding:const EdgeInsets.symmetric(horizontal:14,vertical:8),
          decoration:BoxDecoration(color:AppColors.cyan.withOpacity(0.1),borderRadius:BorderRadius.circular(8),border:Border.all(color:AppColors.cyan.withOpacity(0.3))),
          child:const Text('Retry',style:TextStyle(fontFamily:'Inter',fontSize:11,fontWeight:FontWeight.w600,color:AppColors.cyan))))],
    ]));
}

// ── Server status banner ───────────────────────────────────────
class ServerStatusBanner extends StatelessWidget{
  final bool isUp;
  const ServerStatusBanner({super.key,required this.isUp});
  @override Widget build(BuildContext ctx)=>Container(
    width:double.infinity,padding:const EdgeInsets.symmetric(horizontal:14,vertical:6),
    color:isUp?AppColors.riskLow.withOpacity(0.08):AppColors.riskHigh.withOpacity(0.08),
    child:Row(children:[
      Container(width:6,height:6,decoration:BoxDecoration(shape:BoxShape.circle,color:isUp?AppColors.riskLow:AppColors.riskHigh)),
      const SizedBox(width:8),
      Text(isUp?'FortiSMB API connected  •  http://10.0.2.2:8000':'FortiSMB API offline. Check: uvicorn endpoint.main:app --reload',
        style:TextStyle(fontFamily:'Inter',fontSize:9,color:isUp?AppColors.riskLow:AppColors.riskHigh)),
    ]));
}

// ── SHAP-like factor bar ───────────────────────────────────────
class FactorBar extends StatelessWidget{
  final String label,desc;final double pct;final Color color;
  const FactorBar({super.key,required this.label,required this.desc,required this.pct,required this.color});
  @override Widget build(BuildContext ctx)=>Container(
    margin:const EdgeInsets.only(bottom:10),padding:const EdgeInsets.symmetric(horizontal:12,vertical:11),
    decoration:BoxDecoration(color:AppColors.surface1,borderRadius:BorderRadius.circular(8),border:Border.all(color:color.withOpacity(0.22))),
    child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
      Row(children:[
        Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
          Text(label,style:const TextStyle(fontFamily:'Inter',fontSize:11,fontWeight:FontWeight.w600,color:AppColors.textPrimary)),
          Text(desc,style:const TextStyle(fontFamily:'Inter',fontSize:9,color:AppColors.textSub)),
        ])),
        Text('+${pct.toInt()}%',style:TextStyle(fontFamily:'Inter',fontSize:11,fontWeight:FontWeight.w700,color:color)),
      ]),
      const SizedBox(height:8),
      ClipRRect(borderRadius:BorderRadius.circular(2),child:LinearProgressIndicator(
        value:pct/100,minHeight:4,
        backgroundColor:AppColors.border.withOpacity(0.4),
        valueColor:AlwaysStoppedAnimation(color))),
    ]));
}