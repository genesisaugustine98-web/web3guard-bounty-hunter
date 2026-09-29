/**
 * Web3Guard Cloudflare free-plan admission guard.
 *
 * One SQLite-backed Durable Object provides atomic counters and distributed
 * per-chat rate limiting across Worker isolates.
 */
export const FREE_LIMITS=Object.freeze({
  workersRequestsPerDay:100000,
  durableObjectRequestsPerDay:100000,
  d1ReadsPerDay:5000000,
  d1WritesPerDay:100000,
  queueOpsPerDay:10000,
  r2StorageBytesMonth:10000000000,
  r2ClassAMonth:1000000,
  r2ClassBMonth:10000000,
});
export const SAFE_LIMITS=Object.freeze({
  workersRequestsPerDay:70000,
  durableObjectRequestsPerDay:70000,
  d1ReadsPerDay:3500000,
  d1WritesPerDay:70000,
  queueOpsPerDay:7000,
  r2StorageBytesMonth:7500000000,
  r2ClassAMonth:700000,
  r2ClassBMonth:7000000,
  scanDispatchesPerDay:1000,
});
export const QUEUE_OP_RESERVATION_PER_SCAN=5;
export function utcDay(ts=Date.now()){return new Date(ts).toISOString().slice(0,10);}
export function utcMonth(ts=Date.now()){return new Date(ts).toISOString().slice(0,7);}
function reply(body,status=200){return new Response(JSON.stringify(body),{status,headers:{"content-type":"application/json","cache-control":"no-store"}});}
function positiveInt(value,fallback=0){const n=Number(value);return Number.isFinite(n)&&n>0?Math.floor(n):fallback;}
export class Web3GuardFreeGuard{
  constructor(state){this.state=state;}
  async load(){
    const current=await this.state.storage.get("state");
    const day=utcDay(),month=utcMonth();
    if(!current||current.month!==month)return{day,month,dayCounters:{},monthCounters:{},rates:{}};
    if(current.day!==day)return{day,month,dayCounters:{},monthCounters:current.monthCounters||{},rates:current.rates||{}};
    return current;
  }
  async fetch(request){
    if(request.method!=="POST")return reply({ok:false,error:"method not allowed"},405);
    let body;
    try{body=await request.json();}catch{return reply({ok:false,error:"invalid JSON"},400);}
    const state=await this.load(),failures=[];
    const reservations=Array.isArray(body?.reservations)?body.reservations:[];
    for(const item of reservations){
      const metric=String(item?.metric||"").trim(),units=positiveInt(item?.units),limit=positiveInt(item?.limit);
      if(!metric||!units||!limit)continue;
      const bucket=item?.period==="month"?"monthCounters":"dayCounters",used=Number(state[bucket][metric]||0);
      if(used+units>limit)failures.push({metric,current:used,requested:units,limit});
    }
    const rate=body?.rate;
    if(rate?.key&&positiveInt(rate.limit)){
      const key="rate:"+String(rate.key).slice(0,256),now=Date.now(),windowMs=Math.max(1000,positiveInt(rate.windowMs,60000));
      const values=Array.isArray(state.rates[key])?state.rates[key].filter(t=>Number.isFinite(t)&&now-t<windowMs):[];
      state.rates[key]=values;
      if(values.length>=positiveInt(rate.limit,5))failures.push({metric:"rate_limit",current:values.length,requested:1,limit:rate.limit});
    }
    if(failures.length){await this.state.storage.put("state",state);return reply({ok:false,error:"free_cap_reached",failures},429);}
    for(const item of reservations){
      const metric=String(item?.metric||"").trim(),units=positiveInt(item?.units);
      if(!metric||!units)continue;
      const bucket=item?.period==="month"?"monthCounters":"dayCounters";
      state[bucket][metric]=Number(state[bucket][metric]||0)+units;
    }
    if(rate?.key&&positiveInt(rate.limit)){
      const key="rate:"+String(rate.key).slice(0,256),now=Date.now(),windowMs=Math.max(1000,positiveInt(rate.windowMs,60000));
      const values=Array.isArray(state.rates[key])?state.rates[key].filter(t=>Number.isFinite(t)&&now-t<windowMs):[];
      values.push(now);state.rates[key]=values.slice(-20);
    }
    await this.state.storage.put("state",state);
    return reply({ok:true,day:state.day,month:state.month,dayCounters:state.dayCounters,monthCounters:state.monthCounters});
  }
}
export async function reserveFreeCapacity(env,options={}){
  const binding=env.FREE_GUARD;
  if(!binding){if(String(env.REQUIRE_FREE_GUARD||"0")==="1")return{ok:false,error:"free_guard_binding_missing"};return{ok:true,degraded:true};}
  const stub=binding.get(binding.idFromName("global"));
  const response=await stub.fetch("https://web3guard-free-guard/admit",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(options)});
  let data;try{data=await response.json();}catch{return{ok:false,error:"invalid-free-guard-response"};}
  return data?.ok?data:{ok:false,error:data?.error||"free_guard_rejected",failures:data?.failures||[]};
}
export function scanReservations(env,includeQueue=false){
  const configured=positiveInt(env.MAX_SCANS_PER_DAY,SAFE_LIMITS.scanDispatchesPerDay);
  const reservations=[
    {metric:"worker_requests",units:1,limit:SAFE_LIMITS.workersRequestsPerDay},
    {metric:"do_requests",units:1,limit:SAFE_LIMITS.durableObjectRequestsPerDay},
    {metric:"scan_dispatches",units:1,limit:Math.min(configured,SAFE_LIMITS.scanDispatchesPerDay)},
    ...(env.AUDIT_DB ? [{metric:"d1_writes",units:1,limit:SAFE_LIMITS.d1WritesPerDay}] : []),
  ];
  if(includeQueue)reservations.push({metric:"queue_ops_reserved",units:QUEUE_OP_RESERVATION_PER_SCAN,limit:SAFE_LIMITS.queueOpsPerDay});
  return reservations;
}
