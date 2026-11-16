const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { randomBytes, createHash, timingSafeEqual } = require('node:crypto');
const defaultEvent = require('./default-event.json');

const teacherCode = process.env.TEACHER_CODE?.trim();
if (!teacherCode || teacherCode.length < 12) throw new Error('Set TEACHER_CODE to at least 12 characters.');
const publicOrigin = process.env.PUBLIC_ORIGIN ? new URL(process.env.PUBLIC_ORIGIN).origin : '';
if (publicOrigin && !publicOrigin.startsWith('https://')) throw new Error('PUBLIC_ORIGIN must use HTTPS.');
const storePath = path.resolve(process.env.DATA_FILE || path.join(__dirname,'data','events.json'));
const page = fs.readFileSync(path.join(__dirname,'public','index.html'),'utf8')
  .replace('<meta charset="utf-8">','<meta charset="utf-8"><meta name="shared-mode" content="enabled">');
const token = () => randomBytes(18).toString('base64url');
const emptyGroup = () => ({ area:'', stops:[], status:'draft', note:'', checks:{} });
const createEvent = settings => ({
  settings,
  groups:Array.from({length:settings.groupCount},emptyGroup),
  codes:Array.from({length:settings.groupCount},token),
  revision:0
});
let state = fs.existsSync(storePath) ? JSON.parse(fs.readFileSync(storePath,'utf8')) :
  { active:defaultEvent.id, events:[createEvent(defaultEvent)] };
const sessions = new Map();
const failures = new Map();
const sessionLifetime = 8*60*60*1000;
const sessionCookie = 'kyoto_session';
const areaKeys = ['金閣寺','清水寺'];

function save(next) {
  fs.mkdirSync(path.dirname(storePath),{recursive:true});
  const temporary=storePath+'.tmp';
  fs.writeFileSync(temporary,JSON.stringify(next),{mode:0o600});
  fs.renameSync(temporary,storePath);
  state=next;
}
if (!fs.existsSync(storePath)) save(state);

function send(res,status,value) {
  res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',
    'X-Content-Type-Options':'nosniff'});
  res.end(JSON.stringify(value));
}
function reject(message,status=400) { throw Object.assign(new Error(message),{status}); }
function cookie(req) {
  return (req.headers.cookie || '').match(/(?:^|;\s*)kyoto_session=([A-Za-z0-9_-]+)/)?.[1];
}
function session(req) {
  const id=cookie(req);
  const value=sessions.get(id);
  if (!value || value.expires<=Date.now()) { sessions.delete(id); return null; }
  if (value.role==='student' && findEvent(value.eventId)?.codes[value.group]!==value.groupCode) {
    sessions.delete(id);
    return null;
  }
  return value;
}
function setSession(req,res,value) {
  sessions.delete(cookie(req));
  const id=value?token():'';
  if (value) sessions.set(id,{...value,expires:Date.now()+sessionLifetime});
  res.setHeader('Set-Cookie',`${sessionCookie}=${id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${value?sessionLifetime/1000:0}${publicOrigin?'; Secure':''}`);
}
function findEvent(id) { return state.events.find(item=>item.settings.id===id); }
function revisionFor(item,access) {
  return access?.role==='student'?`${item.settingsRevision || 0}:${item.groups[access.group]?.revision || 0}`:item.revision;
}
function snapshot(access) {
  const item=findEvent(access?.eventId) || findEvent(state.active);
  if (access?.role==='teacher') return {
    access:{role:'teacher'}, settings:item.settings, groups:item.groups, codes:item.codes,
    revision:item.revision, events:state.events.map(event=>({id:event.settings.id,title:event.settings.title,date:event.settings.date}))
  };
  const settings={...item.settings,teachers:[''],checkpoints:item.settings.checkpoints.map(point=>({...point,teacher:''}))};
  const result={access:null,settings,events:[],revision:revisionFor(item,access)};
  if (access?.role==='student' && access.eventId===item.settings.id && item.groups[access.group]) {
    const {area,stops,status,note,areaSelected}=item.groups[access.group];
    result.access={role:'student',group:access.group};
    result.group={area,stops,status,note,areaSelected,checks:{}};
  }
  return result;
}
async function readBody(req) {
  if (req.headers['content-type']?.split(';')[0]!=='application/json') reject('JSON が必要です。',415);
  let bytes=0;
  const chunks=[];
  for await (const chunk of req) {
    bytes+=chunk.length;
    if (bytes>400000) reject('送信内容が大きすぎます。',413);
    chunks.push(chunk);
  }
  try {
    const parsed=JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!parsed || typeof parsed!=='object' || Array.isArray(parsed)) reject('入力形式が正しくありません。');
    return parsed;
  } catch { reject('入力形式が正しくありません。'); }
}
function login(req,res,body) {
  const ip=req.socket.remoteAddress;
  const now=Date.now();
  const attempt=failures.get(ip);
  if (attempt?.until>now && attempt.count>=12) reject('時間をおいてから再度お試しください。',429);
  const code=typeof body.code==='string'?body.code.trim():'';
  let access;
  if (body.role==='teacher' && code.length<=1024) {
    const digest=value=>createHash('sha256').update(value).digest();
    if (timingSafeEqual(digest(code),digest(teacherCode))) access={role:'teacher',eventId:state.active};
  }
  if (body.role==='student' && /^[\w-]{24}$/.test(code)) {
    for (const item of state.events) {
      const group=item.codes.indexOf(code);
      if (group!==-1) { access={role:'student',eventId:item.settings.id,group,groupCode:code}; break; }
    }
  }
  if (!access) {
    failures.set(ip,attempt?.until>now?{until:attempt.until,count:attempt.count+1}:{until:now+60000,count:1});
    reject('コードが一致しません。',401);
  }
  setSession(req,res,access);
  return snapshot(access);
}
const labelKey = name => name.normalize('NFKC').toLowerCase().replace(/\s/g,'');
const clock = value => typeof value==='string' && /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(value);
const string = (value,max) => typeof value==='string' && value.length<=max;
const nonempty = (value,max) => string(value,max) && Boolean(value.trim());
function opposed(settings,area,stops) {
  if (!settings.road) return false;
  const places=[...settings.checkpoints,...(settings.extraVisits || [])];
  return stops.some(stop=>{
    const key=labelKey(stop.name)==='八坂神社' && settings.road==='烏丸通り' &&
      places.some(point=>point.name==='八坂神宮') ? '八坂神宮' : labelKey(stop.name);
    const matches=places.filter(point=>labelKey(point.name)===key);
    return matches.length && !matches.some(point=>point.area==='all'||point.area===area);
  });
}
function validateSettings(input) {
  if (!input || !['title','meeting','finishPlace','areaA','areaB'].every(field=>nonempty(input[field],160)) ||
      input.areaA===input.areaB || !['weather','activityNote','road','purpose'].every(field=>string(input[field],5000)) ||
      !string(input.date,10) || !/^\d{4}-\d\d-\d\d$/.test(input.date) ||
      !Number.isFinite(Date.parse(input.date)) || new Date(input.date).toISOString().slice(0,10)!==input.date ||
      !['meetTime','depart','finishStart','finishEnd'].every(field=>clock(input[field])) ||
      !(input.meetTime<=input.depart && input.depart<=input.finishStart && input.finishStart<=input.finishEnd && input.meetTime<input.finishEnd) ||
      !Number.isInteger(input.groupCount) || input.groupCount<1 || input.groupCount>100 ||
      !Array.isArray(input.teachers) || !input.teachers.length || input.teachers.length>100 ||
      !input.teachers.every(name=>nonempty(name,120)) ||
      !Array.isArray(input.checkpoints) || !input.checkpoints.length || input.checkpoints.length>100 ||
      !Array.isArray(input.extraVisits) || input.extraVisits.length>1000) reject('行事設定を確認してください。');
  const validPlace = point=>point && nonempty(point.name,160) && ['all',...areaKeys].includes(point.area);
  const seen=new Set();
  for (const point of input.checkpoints) {
    if (!validPlace(point) || !Number.isSafeInteger(point.id) || point.id<0 || seen.has(point.id) ||
      !clock(point.open) || point.open<input.meetTime || point.open>=input.finishEnd ||
      (point.close!=='' && (!clock(point.close) || point.close<=point.open || point.close>input.finishEnd)) ||
      (point.teacher!=='' && !input.teachers.includes(point.teacher))) reject('チェックポイントの設定を確認してください。');
    seen.add(point.id);
  }
  if (!input.extraVisits.every(validPlace)) reject('訪問先の設定を確認してください。');
  const fields=['title','date','weather','meeting','meetTime','depart','activityNote','finishPlace','finishStart','finishEnd',
    'areaA','areaB','road','purpose','groupCount','teachers'];
  return {
    ...Object.fromEntries(fields.map(field=>[field,input[field]])),
    checkpoints:input.checkpoints.map(({id,name,area,open,close,teacher})=>({id,name,area,open,close,teacher})),
    extraVisits:input.extraVisits.map(({name,area})=>({name,area}))
  };
}
function reopen(group) {
  if (group.status!=='approved') reject('このプランは承認済みではありません。',409);
  group.status='draft';
  group.note='';
  group.areaSelected=true;
}
function action(access,body) {
  if (!access) reject('コードを入力してログインしてください。',401);
  const current=findEvent(access.eventId);
  if (!current) reject('行事が見つかりません。',404);
  if (body.role!==access.role || (access.role==='student' && body.ownGroup!==access.group))
    reject('ログイン状態が変わりました。画面を更新してください。',409);
  if (body.eventId!==current.settings.id || body.revision!==revisionFor(current,access))
    reject('ほかの端末で更新されました。最新の内容を確認してから再操作してください。',409);
  const next=structuredClone(state);
  const item=next.events.find(event=>event.settings.id===access.eventId);
  const {settings,groups}=item;
  if (access.role==='student') {
    const group=groups[access.group];
    if (!group) reject('この班のアクセスは終了しています。',403);
    if (body.action==='reopen') reopen(group);
    else if (body.action==='plan') {
      if (!['draft','returned'].includes(group.status)) reject('このプランは編集できません。',409);
      if (!areaKeys.includes(body.area) || !Array.isArray(body.stops) || body.stops.length>100 ||
          !body.stops.every(stop=>stop && string(stop.name,80) && (stop.time===''||clock(stop.time)) &&
            string(stop.travel || '',80) && string(stop.goal || '',240))) reject('訪問先の入力を確認してください。');
      if (body.submit===true && (!body.stops.length || body.stops.some((stop,i)=>!stop.name.trim() || !stop.time ||
          (i>0 && stop.time<body.stops[i-1].time)) || opposed(settings,body.area,body.stops))) reject('訪問先の方面と到着予定を確認してください。');
      group.area=body.area;
      group.areaSelected=true;
      group.stops=body.stops.map(({name,time,travel,goal})=>({name,time,travel,goal}));
      if (body.submit===true) { group.status='submitted'; group.note=''; }
    } else reject('この操作は教員のみ行えます。',403);
    group.revision=(group.revision || 0)+1;
  } else if (body.action==='switch') {
    if (!findEvent(body.target)) reject('行事が見つかりません。',404);
    next.active=body.target;
    save(next);
    access.eventId=body.target;
    return snapshot(access);
  } else if (body.action==='settings') {
    const updated=validateSettings(body.settings);
    if (body.create===true) {
      updated.id=token();
      next.events.push(createEvent(updated));
      next.active=updated.id;
      save(next);
      access.eventId=updated.id;
      return snapshot(access);
    }
    updated.id=settings.id;
    if (groups.slice(updated.groupCount).some(group=>group.stops.length || group.areaSelected || group.status!=='draft' || Object.keys(group.checks).length))
      reject('プランや通過記録がある班を除くことはできません。');
    if (groups.some(group=>Object.keys(group.checks).some(id=>!updated.checkpoints.some(point=>point.id===Number(id)))))
      reject('通過記録がある地点は削除できません。');
    while (groups.length<updated.groupCount) { groups.push(emptyGroup()); item.codes.push(token()); }
    groups.length=updated.groupCount;
    item.codes.length=updated.groupCount;
    item.settings=updated;
    item.settingsRevision=(item.settingsRevision || 0)+1;
  } else {
    if (!Number.isInteger(body.group) || body.group<0 || body.group>=groups.length) reject('班が見つかりません。',404);
    const group=groups[body.group];
    if (body.action==='review') {
      if (body.decision==='reopen') reopen(group);
      else {
        if (group.status!=='submitted' || !['approved','returned'].includes(body.decision)) reject('確認できる提出がありません。',409);
        if (body.decision==='returned' && !nonempty(body.note,240)) reject('差し戻し理由を入力してください。');
        if (body.decision==='approved' && opposed(settings,group.area,group.stops)) reject('反対側の訪問先が含まれています。');
        group.status=body.decision;
        group.note=body.decision==='returned'?body.note.trim():'';
      }
      group.revision=(group.revision || 0)+1;
    } else if (body.action==='check') {
      if (!Number.isInteger(body.point) || !settings.checkpoints.some(point=>point.id===body.point) ||
          !settings.teachers.includes(body.staff) || (body.photoId!==undefined &&
          (typeof body.photoId!=='string' || !/^[a-f0-9-]{36}$/.test(body.photoId)))) reject('通過記録の項目を確認してください。');
      const record=group.checks[body.point] || {
        staff:body.staff,time:new Intl.DateTimeFormat('ja-JP',{timeZone:'Asia/Tokyo',month:'numeric',day:'numeric',hour:'2-digit',minute:'2-digit'}).format(new Date()),
        photo:false
      };
      if (body.photoId && !record.photoId) { record.photo=true; record.photoId=body.photoId; }
      group.checks[body.point]=record;
    } else reject('操作が見つかりません。',404);
  }
  item.revision++;
  save(next);
  return snapshot(access);
}

async function handleRequest(req,res) {
  try {
    const url=new URL(req.url,'http://localhost');
    if (req.method==='GET' && ['/', '/index.html'].includes(url.pathname)) {
      res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache',
        'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
        'Content-Security-Policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; media-src blob:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"});
      res.end(page);
      return;
    }
    if (req.method==='GET' && url.pathname==='/api/state') { send(res,200,snapshot(session(req))); return; }
    if (req.method!=='POST' || !['/api/login','/api/logout','/api/action'].includes(url.pathname)) reject('見つかりません。',404);
    if (req.headers.origin!==(publicOrigin || 'http://'+req.headers.host)) reject('このページから操作してください。',403);
    const body=await readBody(req);
    if (url.pathname==='/api/login') { send(res,200,login(req,res,body)); return; }
    if (url.pathname==='/api/logout') { setSession(req,res,null); send(res,200,snapshot(null)); return; }
    send(res,200,action(session(req),body));
  } catch (error) {
    if (!error.status) console.error(error);
    if (!res.headersSent) send(res,error.status || 500,{error:error.status?error.message:'サーバーで保存できませんでした。'});
  }
}
if (require.main===module) {
  const server=http.createServer(handleRequest);
  setInterval(()=>{
    const now=Date.now();
    for (const [id,value] of sessions) if (value.expires<=now) sessions.delete(id);
    for (const [ip,value] of failures) if (value.until<=now) failures.delete(ip);
  },60000).unref();
  server.listen(Number(process.env.PORT || 8787),process.env.HOST || '127.0.0.1',()=>{
    console.log('Kyoto shared site listening on port '+server.address().port);
  });
}
module.exports={handleRequest};
