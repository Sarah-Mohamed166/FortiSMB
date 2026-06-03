import 'package:flutter/material.dart';
import 'package:smooth_page_indicator/smooth_page_indicator.dart';
import '../../core/constants/app_colors.dart';
import '../widgets/shared_widgets.dart';

class OnboardingScreen extends StatefulWidget{
  const OnboardingScreen({super.key});
  @override State<OnboardingScreen> createState()=>_State();
}
class _State extends State<OnboardingScreen>{
  final _ctrl=PageController();int _page=0;
  static const _pages=[
    _P(Icons.shield_outlined,AppColors.cyan,'AI-Powered\nInsider Threat Detection',
      'FortiSMB monitors your workforce using Isolation Forest, Random Forest & XGBoost — trained on millions of real security events.'),
    _P(Icons.auto_awesome_outlined,AppColors.purple,'Gemini-Powered\nXAI Explanations',
      'Every alert comes with a real Gemini 2.0 Flash explanation — not just a risk score. Understand exactly why the AI flagged an event.'),
    _P(Icons.verified_user_outlined,AppColors.riskLow,'HIPAA-Compliant\nRole-Based Access',
      'Only Security Analysts access the full dashboard. Real RBAC enforcement from your FortiSMB backend protects sensitive data.'),
  ];
  @override Widget build(BuildContext ctx)=>Scaffold(
    backgroundColor:AppColors.bgPrimary,
    body:Stack(children:[
      CustomPaint(painter:GridPainter(),size:Size.infinite),
      SafeArea(child:Column(children:[
        Align(alignment:Alignment.topRight,child:TextButton(onPressed:()=>Navigator.pushReplacementNamed(ctx,'/login'),child:const Text('Skip',style:TextStyle(fontFamily:'Inter',fontSize:12,color:AppColors.textMuted)))),
        Expanded(child:PageView.builder(controller:_ctrl,itemCount:_pages.length,onPageChanged:(i)=>setState(()=>_page=i),
          itemBuilder:(_,i)=>Padding(padding:const EdgeInsets.symmetric(horizontal:28),
            child:Column(mainAxisAlignment:MainAxisAlignment.center,children:[
              Container(width:110,height:110,decoration:BoxDecoration(shape:BoxShape.circle,color:_pages[i].color.withOpacity(0.10),border:Border.all(color:_pages[i].color.withOpacity(0.4),width:1.5)),
                child:Icon(_pages[i].icon,color:_pages[i].color,size:52)),
              const SizedBox(height:40),
              Text(_pages[i].title,textAlign:TextAlign.center,style:const TextStyle(fontFamily:'Inter',fontSize:24,fontWeight:FontWeight.w800,color:AppColors.textPrimary,height:1.2,letterSpacing:-0.4)),
              const SizedBox(height:18),
              Text(_pages[i].body,textAlign:TextAlign.center,style:const TextStyle(fontFamily:'Inter',fontSize:13,color:AppColors.textSub,height:1.6)),
            ])))),
        Padding(padding:const EdgeInsets.fromLTRB(24,0,24,32),child:Column(children:[
          SmoothPageIndicator(controller:_ctrl,count:_pages.length,effect:WormEffect(dotHeight:8,dotWidth:8,spacing:10,activeDotColor:AppColors.cyan,dotColor:AppColors.border)),
          const SizedBox(height:28),
          SizedBox(width:double.infinity,height:46,child:ElevatedButton(
            onPressed:(){if(_page<_pages.length-1){_ctrl.nextPage(duration:const Duration(milliseconds:400),curve:Curves.easeOutCubic);}else{Navigator.pushReplacementNamed(ctx,'/login');}},
            child:Text(_page<_pages.length-1?'Continue':'Get Started',style:const TextStyle(fontFamily:'Inter',fontSize:13,fontWeight:FontWeight.w700,color:AppColors.bgPrimary)))),
          if(_page==_pages.length-1)...[const SizedBox(height:10),SizedBox(width:double.infinity,height:42,child:OutlinedButton(onPressed:()=>Navigator.pushReplacementNamed(ctx,'/signup'),child:const Text('Create Account',style:TextStyle(fontFamily:'Inter',fontSize:12,color:AppColors.textSub))))],
        ])),
      ])),
    ]),
  );
}
class _P{final IconData icon;final Color color;final String title,body;
  const _P(this.icon,this.color,this.title,this.body);}