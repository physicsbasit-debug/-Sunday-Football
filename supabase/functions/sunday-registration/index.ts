// Sunday football: public opt-in registration, private roster admin.
// Player PINs are bcrypt-hashed by PostgreSQL; admin key stored as a SHA-256 digest.
const SUPABASE_URL=Deno.env.get("SUPABASE_URL")||"";
const SERVICE_KEY=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||"";
const ALLOWED_ORIGIN="https://physicsbasit-debug.github.io";
const headers={"Content-Type":"application/json","Access-Control-Allow-Origin":ALLOWED_ORIGIN,"Access-Control-Allow-Headers":"content-type,x-sunday-admin,apikey,authorization","Access-Control-Allow-Methods":"POST,OPTIONS","Vary":"Origin","Cache-Control":"no-store"};
const respond=(body,status=200)=>new Response(JSON.stringify(body),{status,headers});
async function pg(path,method="GET",body=null,extraHeaders={}){
 if(!SUPABASE_URL||!SERVICE_KEY)throw new Error("service not configured");
 const response=await fetch(SUPABASE_URL+"/rest/v1/"+path,{method,headers:{"apikey":SERVICE_KEY,"Authorization":"Bearer "+SERVICE_KEY,"Content-Type":"application/json",...extraHeaders},body:body===null?undefined:JSON.stringify(body)});
 const text=await response.text();
 if(!response.ok)throw new Error("Database error "+response.status+" "+text.slice(0,250));
 return text?JSON.parse(text):null;
}
function securePin(){const n=new Uint32Array(1);crypto.getRandomValues(n);return String(10000000+(n[0]%90000000));}
async function hexSha(s){const hash=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s));return Array.from(new Uint8Array(hash)).map(n=>n.toString(16).padStart(2,"0")).join("");}
function constantTimeEqual(a,b){if(typeof a!=="string"||typeof b!=="string"||a.length!==b.length)return false;let diff=0;for(let i=0;i<a.length;i++)diff|=a.charCodeAt(i)^b.charCodeAt(i);return diff===0;}
async function isAdmin(key){
 if(typeof key!=="string"||key.length<32||key.length>200)return false;
 const rows=await pg("sf_reg_admin?select=secret_hash&id=eq.1&limit=1");
 return rows?.length===1&&constantTimeEqual(await hexSha(key),rows[0].secret_hash);
}
async function latestEvent(){
 const rows=await pg("sf_reg_events?select=id,cycle,day_num,is_open,created_at&order=is_open.desc,created_at.desc&limit=1");
 return rows?.[0]||null;
}
async function status(){
 const event=await latestEvent();
 if(!event||!event.is_open)return {ok:true,event:null,players:[],attendingCount:0,respondedCount:0};
 const players=await pg("sf_reg_players?select=player_id,name&active=eq.true&order=name.asc");
 const responses=await pg("sf_reg_responses?select=attending&event_id=eq."+encodeURIComponent(event.id));
 return {ok:true,event,players,attendingCount:responses.filter(x=>x.attending).length,respondedCount:responses.length};
}
async function adminOverview(){
 const event=await latestEvent();
 const players=await pg("sf_reg_players?select=player_id,name,active&order=name.asc");
 const responses=event?await pg("sf_reg_responses?select=player_id,attending,updated_at&event_id=eq."+encodeURIComponent(event.id)):[];
 return {ok:true,event,players,responses,registrationUrl:"https://physicsbasit-debug.github.io/-Sunday-Football/register.html"};
}
async function syncRoster(roster){
 if(!Array.isArray(roster)||roster.length<1||roster.length>120) return respond({error:"تأكد من قائمة اللاعبين (1 إلى 120)."},400);
 const seen=new Set(),clean=[];
 for(const p of roster){
   const id=String(p.id??"").trim(),name=String(p.name??"").trim();
   if(!id||id.length>90||name.length<2||name.length>90||seen.has(id))return respond({error:"توجد بيانات لاعبين غير صالحة أو مكررة."},400);
   seen.add(id);clean.push({id,name,active:p.active!==false});
 }
 const codes=[];
 for(let i=0;i<clean.length;i+=5){
   const batch=clean.slice(i,i+5);
   const results=await Promise.all(batch.map(async p=>{
     const pin=securePin();
     const isNew=await pg("rpc/sf_reg_sync_player","POST",{p_id:p.id,p_name:p.name,p_active:p.active,p_pin:pin});
     return {p,isNew,pin};
   }));
   for(const item of results){if(item.isNew)codes.push({id:item.p.id,name:item.p.name,pin:item.pin});}
 }
 return respond({ok:true,total:clean.length,newPlayers:codes.length,codes,notice:"أرسل رمز كل لاعب إليه على الخاص. لن يظهر الرمز نفسه مرة أخرى."});
}
async function rotatePin(id){
 const rows=await pg("sf_reg_players?select=player_id,name&player_id=eq."+encodeURIComponent(id)+"&limit=1");
 if(!rows.length)return respond({error:"لاعب غير موجود."},404);
 const pin=securePin();const updated=await pg("rpc/sf_reg_reset_pin","POST",{p_id:id,p_pin:pin});
 return respond({ok:!!updated,player:rows[0].name,pin});
}
async function openEvent(cycle,day){
 if(!Number.isInteger(cycle)||cycle<1||cycle>1000000||!Number.isInteger(day)||day<1||day>5)return respond({error:"تحقق من رقم الدورة والتمرين."},400);
 const all=await pg("sf_reg_players?select=player_id&active=eq.true");
 if(all.length<2)return respond({error:"ارفع قائمة اللاعبين أولًا."},400);
 const existing=await pg("sf_reg_events?select=id&cycle=eq."+cycle+"&day_num=eq."+day+"&limit=1");
 await pg("sf_reg_events?is_open=eq.true","PATCH",{is_open:false,updated_at:new Date().toISOString()});
 if(existing.length){
   await pg("sf_reg_events?id=eq."+encodeURIComponent(existing[0].id),"PATCH",{is_open:true,updated_at:new Date().toISOString()});
 }else{
   await pg("sf_reg_events","POST",{cycle,day_num:day,is_open:true},{Prefer:"return=representation"});
 }
 const event=await latestEvent();
 return respond({ok:true,event,preservedResponses:existing.length>0});
}
async function closeEvent(){
 await pg("sf_reg_events?is_open=eq.true","PATCH",{is_open:false,updated_at:new Date().toISOString()});
 return respond({ok:true});
}
Deno.serve(async (req)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers});
 if(req.method!=="POST")return respond({error:"method_not_allowed"},405);
 const origin=req.headers.get("origin");
 if(origin&&origin!==ALLOWED_ORIGIN)return respond({error:"forbidden_origin"},403);
 try{
   const data=await req.json().catch(()=>null);
   if(!data||typeof data.action!=="string")return respond({error:"invalid_request"},400);
   if(data.action==="status")return respond(await status());
   if(data.action==="respond"){
     const eventId=String(data.eventId??""),playerId=String(data.playerId??""),pin=String(data.pin??"");
     if(!/^[0-9a-f-]{36}$/i.test(eventId)||playerId.length<1||playerId.length>90||!/^\d{8}$/.test(pin)||typeof data.attending!=="boolean")return respond({ok:false,error:"invalid_credentials"},400);
     const result=await pg("rpc/sf_reg_submit","POST",{p_event_id:eventId,p_player_id:playerId,p_code:pin,p_attending:data.attending});
     return respond(result,result.ok?200:result.error==="temporarily_locked"?429:400);
   }
   if(!await isAdmin(req.headers.get("x-sunday-admin")))return respond({error:"مفتاح الإدارة غير صحيح."},401);
   if(data.action==="admin_overview")return respond(await adminOverview());
   if(data.action==="sync_roster")return await syncRoster(data.roster);
   if(data.action==="rotate_pin")return await rotatePin(String(data.playerId??""));
   if(data.action==="open_event")return await openEvent(Number(data.cycle),Number(data.day));
   if(data.action==="close_event")return await closeEvent();
   return respond({error:"unknown_action"},400);
 }catch(err){
   console.error("registration endpoint:",String(err).slice(0,240));
   return respond({error:"تعذرت العملية مؤقتًا. حاول مجددًا."},500);
 }
});
