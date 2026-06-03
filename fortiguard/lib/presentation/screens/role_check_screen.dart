import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../core/constants/app_colors.dart';
import '../../data/repositories/app_provider.dart';
import '../widgets/shared_widgets.dart';

class RoleCheckScreen extends StatefulWidget{
  const RoleCheckScreen({super.key});
  @override State<RoleCheckScreen> createState()=>_State();
}
class _State extends State<RoleCheckScreen>{
  int _step=0;
  late String _role,_name;
  bool _done=false;

  static const _steps=['Firebase Auth Token','JWT Validation','RBAC Policy Check','Role Confirmed','Permissions Loaded'];

  @override void didChangeDependencies(){
    super.didChangeDependencies();
    final args=ModalRoute.of(context)?.settings.arguments as Map?;
    _role=args?['role'] as String?? 'Security Analyst';
    _name=args?['name'] as String?? 'EMP-0082';
    _tick();
  }

  void _tick() async {
    for(int i=0;i<_steps.length;i++){
      await Future.delayed(const Duration(milliseconds:430));
      if(mounted)setState(()=>_step=i+1);
    }
    await Future.delayed(const Duration(milliseconds:400));
    if(!mounted)return;
    setState(()=>_done=true);
    final isAnalyst=_role=='Security Analyst';
    context.read<AuthProvider>().login(_role,name:_name);
    await Future.delayed(const Duration(milliseconds:600));
    if(!mounted)return;
    if(isAnalyst){Navigator.pushReplacementNamed(context,'/dashboard');}
    else{Navigator.pushReplacementNamed(context,'/access-denied',arguments:_role);}
  }

  @override Widget build(BuildContext ctx)=>Scaffold(
    backgroundColor:AppColors.bgPrimary,
    body:Stack(children:[
      CustomPaint(painter:GridPainter(),size:Size.infinite),
      Positioned(top:-30,left:-30,child:GlowOrb(color:AppColors.gold,size:200,opacity:0.07)),
      SafeArea(child:Padding(padding:const EdgeInsets.symmetric(horizontal:22),
        child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
          const SizedBox(height:14),
          Row(children:[
            Container(width:28,height:28,decoration:BoxDecoration(shape:BoxShape.circle,color:AppColors.gold.withOpacity(0.12),border:Border.all(color:AppColors.gold.withOpacity(0.4))),
              child:const Center(child:Text('◆',style:TextStyle(fontSize:12,color:AppColors.gold)))),
            const SizedBox(width:10),
            const Text('FortiGuard',style:TextStyle(fontFamily:'Inter',fontSize:13,fontWeight:FontWeight.w600,color:AppColors.textPrimary)),
          ]),
          const SizedBox(height:50),
          Center(child:Container(width:72,height:72,decoration:BoxDecoration(borderRadius:BorderRadius.circular(18),color:AppColors.gold.withOpacity(0.10),border:Border.all(color:AppColors.gold.withOpacity(0.4),width:1.5)),
            child:const Center(child:Text('◆',style:TextStyle(fontSize:28,color:AppColors.gold))))),
          const SizedBox(height:26),
          const Center(child:Text('Verifying Access Level',style:TextStyle(fontFamily:'Inter',fontSize:18,fontWeight:FontWeight.w800,color:AppColors.textPrimary))),
          const SizedBox(height:6),
          Center(child:Text('Role: $_role',style:const TextStyle(fontFamily:'Inter',fontSize:11,color:AppColors.textSub))),
          const SizedBox(height:8),
          Center(child:SizedBox(width:200,child:LinearProgressIndicator(value:_step/_steps.length,minHeight:3,backgroundColor:AppColors.border.withOpacity(0.4),valueColor:const AlwaysStoppedAnimation(AppColors.gold)))),
          const SizedBox(height:26),
          ...List.generate(_steps.length,(i){
            final done=i<_step;final c=done?AppColors.riskLow:AppColors.border;
            return Container(margin:const EdgeInsets.only(bottom:8),padding:const EdgeInsets.symmetric(horizontal:14,vertical:10),
              decoration:BoxDecoration(color:AppColors.surface1,borderRadius:BorderRadius.circular(8),border:Border.all(color:done?c.withOpacity(0.3):AppColors.border)),
              child:Row(children:[
                Container(width:7,height:7,decoration:BoxDecoration(shape:BoxShape.circle,color:c)),
                const SizedBox(width:10),
                Expanded(child:Text(_steps[i],style:TextStyle(fontFamily:'Inter',fontSize:11,color:done?AppColors.textPrimary:AppColors.textDim))),
                if(done)const Text('✓ Verified',style:TextStyle(fontFamily:'Inter',fontSize:9,fontWeight:FontWeight.w700,color:AppColors.riskLow))
                else if(i==_step)const SizedBox(width:14,height:14,child:CircularProgressIndicator(strokeWidth:1.5,color:AppColors.gold)),
              ]));
          }),
          if(_done)...[
            const SizedBox(height:20),
            AnimatedOpacity(opacity:1,duration:const Duration(milliseconds:400),child:Container(
              width:double.infinity,padding:const EdgeInsets.all(14),
              decoration:BoxDecoration(color:(_role=='Security Analyst'?AppColors.cyan:AppColors.riskHigh).withOpacity(0.07),
                borderRadius:BorderRadius.circular(10),border:Border.all(color:(_role=='Security Analyst'?AppColors.cyan:AppColors.riskHigh).withOpacity(0.45),width:1.5)),
              child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                Text(_role=='Security Analyst'?'✓  Access Granted':'✗  Access Denied',
                  style:TextStyle(fontFamily:'Inter',fontSize:12,fontWeight:FontWeight.w700,color:_role=='Security Analyst'?AppColors.cyan:AppColors.riskHigh)),
                const SizedBox(height:4),
                Text(_role=='Security Analyst'?'Role: Security Analyst  •  Full SOC Access':'Role: $_role  •  Dashboard restricted',
                  style:const TextStyle(fontFamily:'Inter',fontSize:10,color:AppColors.textSub)),
              ]))),
          ],
        ]))),
    ]),
  );
}