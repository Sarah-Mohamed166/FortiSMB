import 'package:flutter/material.dart';
import '../../core/constants/app_colors.dart';
import '../widgets/shared_widgets.dart';

class AccessDeniedScreen extends StatelessWidget{const AccessDeniedScreen({super.key});
  @override Widget build(BuildContext ctx){
    final role=ModalRoute.of(ctx)?.settings.arguments as String?? 'Unknown';
    return Scaffold(backgroundColor:AppColors.bgPrimary,
      body:Stack(children:[
        CustomPaint(painter:GridPainter(),size:Size.infinite),
        Positioned(top:-30,left:-30,child:GlowOrb(color:AppColors.riskHigh,size:240,opacity:0.07)),
        SafeArea(child:Padding(padding:const EdgeInsets.symmetric(horizontal:28),
          child:Column(mainAxisAlignment:MainAxisAlignment.center,children:[
            Container(width:90,height:90,decoration:BoxDecoration(shape:BoxShape.circle,color:AppColors.riskHigh.withOpacity(0.10),border:Border.all(color:AppColors.riskHigh.withOpacity(0.45),width:1.5)),
              child:const Center(child:Text('✗',style:TextStyle(fontSize:36,color:AppColors.riskHigh)))),
            const SizedBox(height:28),
            const Text('Access Denied',style:TextStyle(fontFamily:'Inter',fontSize:26,fontWeight:FontWeight.w800,color:AppColors.riskHigh,letterSpacing:-0.4)),
            const SizedBox(height:10),
            Text("Your role '$role' does not have permission to access the FortiGuard Security Dashboard.",textAlign:TextAlign.center,style:const TextStyle(fontFamily:'Inter',fontSize:12,color:AppColors.textSub,height:1.6)),
            const SizedBox(height:24),
            Container(width:double.infinity,padding:const EdgeInsets.all(14),decoration:BoxDecoration(color:AppColors.riskHigh.withOpacity(0.08),borderRadius:BorderRadius.circular(10),border:Border.all(color:AppColors.riskHigh.withOpacity(0.35))),
              child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                const Text('Access Details',style:TextStyle(fontFamily:'Inter',fontSize:10,fontWeight:FontWeight.w700,color:AppColors.riskHigh)),const SizedBox(height:8),
                _row('Error Code','RBAC-403'),_row('Your Role',role),_row('Required','Security Analyst'),_row('Access','Full SOC Dashboard'),
              ])),
            const SizedBox(height:16),
            Container(width:double.infinity,padding:const EdgeInsets.all(12),decoration:BoxDecoration(color:AppColors.surface1,borderRadius:BorderRadius.circular(10),border:Border.all(color:AppColors.border)),
              child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                const Text('What Security Analyst can access:',style:TextStyle(fontFamily:'Inter',fontSize:10,fontWeight:FontWeight.w600,color:AppColors.textPrimary)),const SizedBox(height:8),
                for(final p in ['Dashboard (Live Sysmon Logs)','Check Logs Screen','Alerts Screen','Risk Analysis → POST /predict','XAI Explanation (Gemini)','Profile / Settings'])
                  Padding(padding:const EdgeInsets.only(bottom:4),child:Row(children:[const Icon(Icons.check,size:12,color:AppColors.riskLow),const SizedBox(width:8),Text(p,style:const TextStyle(fontFamily:'Inter',fontSize:10,color:AppColors.textSub))])),
              ])),
            const SizedBox(height:24),
            SizedBox(width:double.infinity,height:46,child:ElevatedButton(onPressed:()=>Navigator.pushReplacementNamed(ctx,'/login'),child:const Text('Login with Correct Role',style:TextStyle(fontFamily:'Inter',fontSize:13,fontWeight:FontWeight.w700,color:AppColors.bgPrimary)))),
            const SizedBox(height:12),
            TextButton(onPressed:()=>Navigator.pushReplacementNamed(ctx,'/login'),child:const Text('Back to Login',style:TextStyle(fontFamily:'Inter',fontSize:11,color:AppColors.textMuted))),
            const SizedBox(height:16),
            const Text('Contact your IT Security Administrator for access.',textAlign:TextAlign.center,style:TextStyle(fontFamily:'Inter',fontSize:9,color:AppColors.textDim)),
          ]))),
      ]),
    );
  }
  static Widget _row(String k,String v)=>Padding(padding:const EdgeInsets.only(bottom:5),child:Row(children:[SizedBox(width:80,child:Text(k,style:const TextStyle(fontFamily:'Inter',fontSize:9,color:AppColors.textDim))),Text(v,style:const TextStyle(fontFamily:'Inter',fontSize:10,fontWeight:FontWeight.w600,color:AppColors.riskHigh))]));
}