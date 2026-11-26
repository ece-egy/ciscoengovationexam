const express=require('express'),crypto=require('crypto'),fs=require('fs'),path=require('path'),nodemailer=require('nodemailer');
const app=express(),ENFORCE_IP=process.env.ENFORCE_IP!=='0';
app.set('trust proxy',process.env.TRUST_PROXY==='1');
app.use(express.json({limit:'200kb'}));
app.use((q,s,n)=>{s.set({'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'POST,OPTIONS'});q.method==='OPTIONS'?s.sendStatus(204):n()});
const fail=(s,m,c=400)=>s.status(c).json({error:m}),wrap=f=>(q,s)=>f(q,s).catch(e=>{console.error(e);fail(s,'خطأ بالسيرفر أو تعذر إرسال الإيميل',500)});
const hits={};setInterval(()=>{for(const k in hits)delete hits[k]},60000);
app.use('/api',(q,s,n)=>(hits[q.ip]=(hits[q.ip]||0)+1)>30?fail(s,'محاولات كثيرة، انتظر دقيقة',429):n());
const DB=path.join(__dirname,'db.json');let db=fs.existsSync(DB)?JSON.parse(fs.readFileSync(DB)):{users:{}};
const save=()=>fs.writeFileSync(DB,JSON.stringify(db,null,1)),sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const hashPw=(p,salt)=>crypto.scryptSync(p,salt,32).toString('hex'),norm=s=>s.toLowerCase().replace(/\s+/g,' ').trim();
const key=e=>String(e||'').trim().toLowerCase(),all=()=>Object.values(db.users);
const mailer=process.env.SMTP_HOST?nodemailer.createTransport({host:process.env.SMTP_HOST,port:+process.env.SMTP_PORT||587,auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}}):null;
async function sendCode(u){const c=String(crypto.randomInt(100000,1000000));u.otp={h:sha(c+u.email),exp:Date.now()+6e5,tries:0};save();
 if(!mailer){console.log(`[DEV] verification code for ${u.email}: ${c}`);return}
 await mailer.sendMail({from:process.env.MAIL_FROM||process.env.SMTP_USER,to:u.email,subject:'Cisco Exam - Verification Code',text:`Your verification code: ${c}\nValid for 10 minutes.`})}

app.post('/api/register',wrap(async(q,s)=>{
 const{name,pass,deviceId}=q.body,e=key(q.body.email),n=String(name||'').trim();
 if(!n||!/^\S+@\S+\.\S+$/.test(e)||String(pass||'').length<6||!deviceId)return fail(s,'بيانات غير صحيحة (كلمة المرور 6 أحرف على الأقل)');
 const U=all();
 if(db.users[e])return fail(s,'هذا البريد مسجل بالفعل');
 if(U.some(u=>norm(u.name)===norm(n)))return fail(s,'اسم المستخدم مسجل بالفعل');
 if(U.some(u=>u.deviceId===deviceId))return fail(s,'تم التسجيل من هذا الجهاز من قبل');
 if(ENFORCE_IP&&U.some(u=>u.ip===q.ip))return fail(s,'تم التسجيل من هذا العنوان (IP) من قبل');
 const salt=crypto.randomBytes(16).toString('hex');
 const u=db.users[e]={email:e,name:n,salt,pw:hashPw(String(pass),salt),deviceId,ip:q.ip,status:'registered',created:Date.now()};
 await sendCode(u);s.json({ok:true})}));

app.post('/api/login',wrap(async(q,s)=>{
 const u=db.users[key(q.body.email)];
 if(!u||hashPw(String(q.body.pass||''),u.salt)!==u.pw)return fail(s,'بيانات الدخول غير صحيحة');
 if(u.status==='passed')return fail(s,'لقد اجتزت الاختبار — ادخل باستخدام كود الشهادة');
 if(u.status!=='registered')return fail(s,'لقد دخلت الاختبار من قبل ولا يمكن الدخول مرة أخرى');
 await sendCode(u);s.json({ok:true})}));

app.post('/api/verify',wrap(async(q,s)=>{
 const u=db.users[key(q.body.email)],o=u&&u.otp;
 if(!o||o.exp<Date.now()||o.tries>=5)return fail(s,'الكود منتهي أو تجاوزت المحاولات، سجّل الدخول من جديد');
 o.tries++;if(o.h!==sha(String(q.body.code||'').trim()+u.email)){save();return fail(s,'كود غير صحيح')}
 if(u.status!=='registered')return fail(s,'لقد دخلت الاختبار من قبل');
 const d=q.body.deviceId;
 if(all().some(x=>x!==u&&x.status!=='registered'&&(x.deviceId===d||(ENFORCE_IP&&x.ip===q.ip))))return fail(s,'تم أداء الاختبار من هذا الجهاز/العنوان من قبل');
 Object.assign(u,{otp:null,status:'started',startedAt:Date.now(),token:crypto.randomBytes(24).toString('hex'),deviceId:d||u.deviceId,ip:q.ip});save();
 s.json({ok:true,token:u.token,name:u.name})}));

app.post('/api/submit',(q,s)=>{
 const b=q.body,u=all().find(x=>x.token&&x.token===b.token&&x.status==='started');
 if(!u)return fail(s,'جلسة غير صالحة أو تم التسليم من قبل');
 const c=(v,m)=>Math.max(0,Math.min(m,Math.round(+v)||0)),r={theory:c(b.theory,40),pt:c(b.pt,30),gns3:c(b.gns3,30)};
 r.total=r.theory+r.pt+r.gns3;r.date=new Date().toISOString();
 r.logs=String(b.logs||'').slice(0,30000).replace(/<(?!\/?(li|b)\b)[^>]*>/gi,'').replace(/\son\w+\s*=/gi,' x=');
 const passed=r.total>=70&&r.pt>0&&r.gns3>0;
 u.token=null;u.result=r;u.status=passed?'passed':'failed';
 if(passed)u.certCode='CCNA-'+[0,1,2].map(()=>crypto.randomBytes(2).toString('hex').toUpperCase()).join('-');
 save();s.json({ok:true,passed,certCode:u.certCode||null})});

app.post('/api/cert-login',(q,s)=>{
 const code=String(q.body.code||'').trim().toUpperCase(),u=all().find(x=>x.certCode&&x.certCode===code);
 if(!u)return fail(s,'كود الشهادة غير صحيح');
 s.json({name:u.name,certCode:u.certCode,...u.result})});

app.get('/',(q,s)=>s.sendFile(path.join(__dirname,'cisco-exam.html')));
app.listen(process.env.PORT||3000,()=>console.log('Running on http://localhost:'+(process.env.PORT||3000)));
