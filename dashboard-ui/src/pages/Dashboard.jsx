import { useState } from 'react';
import {
  AlertTriangle, Shield, Zap, TrendingUp, Clock,
  ChevronRight, MapPin, Building2, FileSearch,
} from 'lucide-react';
import NetworkTopology from '../components/NetworkTopology';
import { formatCountryDisplay } from '../utils/countryDisplay';

/* ── Stat card ── */
function StatCard({ icon: Icon, value, label, color, trend }) {
  return (
    <div className="card" style={{ padding:'14px 16px', flex:1, minWidth:0 }}>
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between' }}>
        <Icon size={17} color={color} strokeWidth={1.8} />
        {trend && <TrendingUp size={12} color="#22c55e" opacity={0.7} />}
      </div>
      <div style={{ marginTop:9, fontSize:26, fontWeight:700, color, lineHeight:1 }}>{value}</div>
      <div style={{ marginTop:4, fontSize:11, color:'#8b8fa8' }}>{label}</div>
    </div>
  );
}

/* ── Severity badge ── */
function SevBadge({ sev }) {
  return <span className={`badge badge-${sev}`}>{sev === 'LOG_ONLY' ? 'LOG' : sev}</span>;
}

/* ── Mapare decizie → label afișat ── */
function mapDecizieLabel(decizie) {
  const map = {
    'drop': 'DROP',
    'rate_limit_agresiv': 'RATE-LIMIT',
    'rate_limit_permisiv': 'RATE-LIMIT',
    'log_only': 'MONITOR',
  };
  return map[decizie] || decizie?.toUpperCase() || '—';
}

/* ── Action pill ── */
const ACTION_STYLE = {
  DROP:        { bg:'rgba(239,68,68,.15)',   c:'#ef4444', b:'rgba(239,68,68,.3)' },
  'RATE-LIMIT':{ bg:'rgba(59,130,246,.15)',  c:'#60a5fa', b:'rgba(59,130,246,.3)' },
  MONITOR:     { bg:'rgba(34,197,94,.12)',   c:'#4ade80', b:'rgba(34,197,94,.25)' },
  PREVIEW:     { bg:'rgba(90,93,117,.15)',   c:'#9ca3af', b:'rgba(90,93,117,.3)' },
};
function ActionPill({ label }) {
  const s = ACTION_STYLE[label] || ACTION_STYLE.PREVIEW;
  return (
    <span style={{ fontSize:10, fontWeight:700, padding:'2px 8px', borderRadius:4,
      letterSpacing:.4, background:s.bg, color:s.c, border:`1px solid ${s.b}` }}>
      {label}
    </span>
  );
}

/* ── AbuseIPDB gauge ── */
function AbuseGauge({ score }) {
  const cx = 100, cy = 105, R = 72;
  const startDeg = 135, endDeg = 405;
  const sweepDeg = endDeg - startDeg;

  const polar = (deg, r) => {
    const rad = (deg * Math.PI) / 180;
    return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
  };

  const displayScore = score >= 0 ? score : 0;
  const pct  = Math.min(Math.max(displayScore, 0), 100) / 100;
  const fillDeg = startDeg + pct * sweepDeg;
  const color = displayScore >= 75 ? '#ef4444' : displayScore >= 50 ? '#f59e0b' : '#22c55e';

  const arc = (from, to) => {
    const s = polar(from, R), e = polar(to, R);
    const large = (to - from) > 180 ? 1 : 0;
    return `M${s.x},${s.y} A${R},${R} 0 ${large},1 ${e.x},${e.y}`;
  };

  return (
    <svg viewBox="0 0 200 155" width="100%" style={{ maxWidth:210, display:'block', margin:'0 auto' }}>
      <path d={arc(startDeg, endDeg)} fill="none" stroke="#1e2030" strokeWidth={11} strokeLinecap="round"/>
      {displayScore > 0 && (
        <path d={arc(startDeg, fillDeg)} fill="none" stroke={color} strokeWidth={11} strokeLinecap="round"/>
      )}
      <text x={cx} y={cy + 8} textAnchor="middle"
        fontSize={38} fontWeight={700} fill={score >= 0 ? color : '#5a5d75'} fontFamily="Inter,sans-serif">
        {score >= 0 ? score : 'N/A'}
      </text>
      <text x={cx} y={cy + 28} textAnchor="middle"
        fontSize={13} fill="#5a5d75" fontFamily="Inter,sans-serif">
        / 100
      </text>
    </svg>
  );
}

/* ── Raport incident (threat intel + rezumat) — fără etichetă „template AI” ── */
function AIReport({ incident }) {
  if (!incident || !incident.ai_verdict) return (
    <div className="card" style={{ padding:'20px', color:'#5a5d75', fontSize:12, textAlign:'center' }}>
      Selectează o amenințare activă pentru a vedea raportul detaliat.
    </div>
  );

  const ai = incident.ai_verdict;
  const abuse = incident.abuseipdb || {};
  const whois = incident.whois || {};
  const abuseScore = abuse.score != null ? Number(abuse.score) : -1;
  const countryLine = formatCountryDisplay(abuse, whois);
  const orgLine = (abuse.isp && String(abuse.isp).trim()) || whois.organization || '—';
  const recs = Array.isArray(ai.recomandari) ? ai.recomandari.filter(Boolean) : [];

  return (
    <div className="card" style={{ padding:'18px 20px' }}>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:16 }}>
        <div style={{ display:'flex', alignItems:'center', gap:9 }}>
          <div style={{
            width:30, height:30, borderRadius:8,
            background:'rgba(148,163,184,.08)', border:'1px solid rgba(148,163,184,.18)',
            display:'flex', alignItems:'center', justifyContent:'center',
          }}>
            <FileSearch size={16} color="#94a3b8" />
          </div>
          <span style={{ fontSize:14, fontWeight:700, color:'#e2e4f0' }}>Raport incident</span>
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:5, fontSize:11, color:'#5a5d75' }}>
          <Clock size={11} />
          Analiză în {incident.ai_elapsed_seconds?.toFixed(1) ?? '—'}s
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'210px 1fr 1fr', gap:14 }}>

        <div>
          <div style={{ fontSize:11, color:'#8b8fa8', marginBottom:8 }}>Scor încredere AbuseIPDB</div>
          <AbuseGauge score={abuseScore} />
          {abuse.total_reports != null && abuse.total_reports > 0 && (
            <div style={{ textAlign:'center', fontSize:10, color:'#5a5d75', marginTop:4 }}>
              {Number(abuse.total_reports).toLocaleString('ro-RO')} rapoarte
            </div>
          )}
          {abuse.is_tor && (
            <div style={{ textAlign:'center', fontSize:10, color:'#ef4444', marginTop:2 }}>
              Nod Tor (exit)
            </div>
          )}
        </div>

        <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
          <div style={{
            background:'#1a1b25', border:'1px solid #22243a', borderRadius:8, padding:'10px 13px',
          }}>
            <div style={{ display:'flex', alignItems:'center', gap:5, fontSize:10, color:'#5a5d75', marginBottom:4 }}>
              <Building2 size={11} /> Organizație / ISP
            </div>
            <div style={{ fontSize:13, fontWeight:600, color:'#e2e4f0' }}>{orgLine}</div>
          </div>

          <div style={{
            background:'#1a1b25', border:'1px solid #22243a', borderRadius:8, padding:'10px 13px',
          }}>
            <div style={{ display:'flex', alignItems:'center', gap:5, fontSize:10, color:'#5a5d75', marginBottom:4 }}>
              <MapPin size={11} /> Țară
            </div>
            <div style={{ fontSize:13, fontWeight:600, color:'#e2e4f0' }}>{countryLine}</div>
          </div>

          <div style={{
            background:'#1a1b25', border:'1px solid #22243a', borderRadius:8, padding:'10px 13px', flex:1,
          }}>
            <div style={{ fontSize:10, fontWeight:700, color:'#94a3b8', marginBottom:6, textTransform:'uppercase', letterSpacing:.5 }}>
              Rezumat
            </div>
            <div style={{ fontSize:11, color:'#a1a7bb', lineHeight:1.65 }}>
              {ai.explicatie || 'Nu există încă un rezumat pentru acest incident.'}
            </div>
          </div>
        </div>

        <div style={{
          background:'#1a1b25', border:'1px solid #22243a', borderRadius:8, padding:'14px 15px',
          display:'flex', flexDirection:'column', gap:12,
        }}>
          {ai.mitre_ids?.length > 0 && (
            <div>
              <div style={{ fontSize:10, color:'#5a5d75', marginBottom:6 }}>MITRE ATT&CK</div>
              <div style={{ display:'flex', gap:5, flexWrap:'wrap' }}>
                {ai.mitre_ids.map((id, i) => (
                  <span key={id} style={{
                    background:'rgba(96,165,250,.10)', color:'#7dd3fc',
                    padding:'2px 8px', borderRadius:4, fontSize:10, fontWeight:700,
                    border:'1px solid rgba(125,211,252,.22)',
                  }}>
                    {id}{ai.mitre_names?.[i] ? ` — ${ai.mitre_names[i]}` : ''}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div>
            <div style={{ fontSize:12, fontWeight:700, color:'#e2e4f0', marginBottom:10 }}>
              Acțiuni recomandate
            </div>
            <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
              {recs.length === 0 ? (
                <div style={{ fontSize:11, color:'#5a5d75' }}>Nu există recomandări în răspunsul modelului.</div>
              ) : (
                recs.map((rec, i) => (
                  <div key={i} style={{ display:'flex', gap:9, fontSize:11, color:'#a1a7bb', lineHeight:1.5 }}>
                    <span style={{ color:'#ca8a04', fontSize:8, marginTop:3, flexShrink:0 }}>◆</span>
                    {rec}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ══ Dashboard page ══ */
export default function Dashboard({ stats, incidents, devices, timeline, blocks }) {
  const [selectedId, setSelectedId] = useState(null);

  const activeIncidents = incidents.filter(i => i.status === 'active').slice(0, 6);

  const formatExpiry = secs => {
    if (!secs || secs <= 0) return '—';
    const m = Math.floor(secs / 60), s = secs % 60;
    return `${m}:${String(s).padStart(2,'0')}`;
  };

  // Detection rate din date reale
  const totalWithAction = incidents.filter(i => i.decizie !== 'log_only').length;
  const detectionRate = incidents.length > 0
    ? Math.round((totalWithAction / incidents.length) * 100 * 10) / 10
    : 0;

  // Incidentul selectat — din incidents (are ai_verdict, abuseipdb, whois)
  const selectedIncident = selectedId
    ? incidents.find(i => i.id === selectedId)
    : (activeIncidents.length > 0 ? activeIncidents[0] : null);

  return (
    <div className="page" style={{ display:'flex', flexDirection:'column', gap:14 }}>

      {/* ── Stats row ── */}
      <div style={{ display:'flex', gap:12 }}>
        <StatCard icon={AlertTriangle} value={stats?.total_incidents ?? '—'} label="Total Incidents" color="#ef4444" />
        <StatCard icon={Shield}        value={stats?.active_blocks ?? '—'}   label="Active Blocks"  color="#f59e0b" />
        <StatCard icon={Zap}           value={stats?.avg_ai_response ? `${stats.avg_ai_response}s` : '—'} label="Avg AI Response" color="#60a5fa" />
        <StatCard icon={TrendingUp}    value={`${detectionRate}%`}           label="Detection Rate"  color="#22c55e" trend />
      </div>

      {/* ── Main grid ── */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 380px', gap:12 }}>

        {/* Topology */}
        <div className="card" style={{ padding:'13px 15px', display:'flex', flexDirection:'column', gap:10 }}>
          <div style={{ fontSize:13, fontWeight:700 }}>Network Topology</div>
          <div style={{ height:420, flexShrink:0, minHeight:380 }}>
            <NetworkTopology
              devices={devices}
              activeIncident={selectedIncident || activeIncidents[0] || null}
            />
          </div>
          <div style={{ borderTop:'1px solid #1e2030', paddingTop:10, display:'flex', justifyContent:'space-between', alignItems:'flex-start' }}>
            <div>
              <div style={{ fontSize:11, fontWeight:600, color:'#8b8fa8', marginBottom:6 }}>Network Status</div>
              <div style={{ display:'flex', gap:14 }}>
                {[['#22c55e','Online'],['#f59e0b','Warning'],['#ef4444','Alert'],['#6b7280','Offline']].map(([c,l]) => (
                  <div key={l} style={{ display:'flex', alignItems:'center', gap:5, fontSize:11, color:'#8b8fa8' }}>
                    <span style={{ width:7, height:7, borderRadius:'50%', background:c, boxShadow:`0 0 5px ${c}66` }}/>
                    {l}
                  </div>
                ))}
              </div>
            </div>
            <div style={{ fontSize:10, color:'#5a5d75', textAlign:'right', lineHeight:1.7 }}>
              Click nodes for details<br/>Drag to reposition<br/>Scroll to zoom
            </div>
          </div>
        </div>

        {/* Active Threats */}
        <div className="card" style={{ padding:'13px 15px', display:'flex', flexDirection:'column' }}>
          <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:10 }}>
            <div style={{ display:'flex', alignItems:'center', gap:7 }}>
              <span style={{ fontSize:13, fontWeight:700 }}>Active Threats</span>
              {activeIncidents.length > 0 && (
                <span style={{
                  background:'#ef4444', color:'#fff', borderRadius:'50%',
                  width:17, height:17, display:'flex', alignItems:'center', justifyContent:'center',
                  fontSize:10, fontWeight:700,
                }}>{activeIncidents.length}</span>
              )}
            </div>
            <AlertTriangle size={13} color="#f59e0b" />
          </div>

          <div style={{ flex:1, overflowY:'auto', display:'flex', flexDirection:'column', gap:7 }}>
            {activeIncidents.length === 0 && (
              <div style={{ textAlign:'center', paddingTop:40 }}>
                <Shield size={28} color="#22c55e" style={{ opacity:0.5, marginBottom:8 }} />
                <div style={{ color:'#5a5d75', fontSize:12 }}>No active threats</div>
                <div style={{ color:'#3a3d55', fontSize:10, marginTop:4 }}>System operating normally</div>
              </div>
            )}
            {activeIncidents.map(inc => {
              const blk = blocks.blocks?.find(b => b.incident_id === inc.id);
              const conf = inc.ai_verdict?.confidence ? Math.round(inc.ai_verdict.confidence * 100) : null;
              const isOn = selectedId === inc.id;
              const leftColor = inc.severitate==='HIGH'?'#ef4444':inc.severitate==='MEDIUM'?'#f59e0b':'#3b82f6';
              const tipAtac = inc.ai_verdict?.tip_atac || `Anomaly (ratio ${inc.ratio}x)`;
              const decizieLabel = mapDecizieLabel(inc.decizie);

              return (
                <div key={inc.id}
                  onClick={() => setSelectedId(isOn ? null : inc.id)}
                  style={{
                    background: isOn ? '#1e2030' : '#1a1b25',
                    border:`1px solid ${isOn ? '#2a2d45' : '#1e2030'}`,
                    borderLeft:`3px solid ${leftColor}`,
                    borderRadius:8, padding:'9px 11px', cursor:'pointer', transition:'all .12s',
                  }}
                >
                  <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:4 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:5 }}>
                      <SevBadge sev={inc.severitate} />
                      <span style={{ fontSize:11, fontWeight:600, color:'#e2e4f0' }}>{tipAtac}</span>
                    </div>
                    <ActionPill label={decizieLabel} />
                  </div>

                  <div style={{ display:'flex', alignItems:'center', gap:4, fontSize:10, color:'#8b8fa8', marginBottom:3 }}>
                    <span style={{ color:'#ef4444', fontWeight:600, fontFamily:'monospace' }}>{inc.sursa_ip}</span>
                    <ChevronRight size={9} />
                    <span>{inc.dispozitiv_victima?.replace(/_/g,' ') || '—'}</span>
                  </div>

                  <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', fontSize:10 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:6, color:'#5a5d75' }}>
                      {inc.ai_verdict?.mitre_ids?.[0] && (
                        <span style={{ color:'#60a5fa', fontWeight:600 }}>
                          MITRE: {inc.ai_verdict.mitre_ids[0]}
                        </span>
                      )}
                      {blk?.remaining_secunde > 0 && (
                        <span style={{ display:'flex', alignItems:'center', gap:3 }}>
                          <Clock size={9}/> Expires in {formatExpiry(blk.remaining_secunde)}
                        </span>
                      )}
                    </div>
                    {conf !== null && (
                      <span style={{ color:'#60a5fa', fontWeight:700 }}>◎ {conf}%</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── AI Intelligence Report — full width ── */}
      <AIReport incident={selectedIncident} />

    </div>
  );
}
