import { useState, useMemo, useEffect } from 'react';
import {
  Search, ExternalLink, X, Network,
  Router, Server, Thermometer, Lock, Camera, Plug, Globe, AlertTriangle,
} from 'lucide-react';

const ICON_MAP = {
  router:            Router,
  server:            Server,
  thermometer:       Thermometer,
  lock:              Lock,
  camera:            Camera,
  plug:              Plug,
  globe:             Globe,
  'alert-triangle':  AlertTriangle,
};

/* ── Mapare current_action din API → label afișat ── */
function mapActionLabel(action) {
  const map = {
    'drop': 'DROP',
    'rate_limit': 'RATE-LIMIT',
    'rate_limit_agresiv': 'RATE-LIMIT',
    'rate_limit_permisiv': 'RATE-LIMIT',
    'isolated': 'ISOLATED',
    'none': 'NONE',
  };
  return map[action] || action?.toUpperCase() || 'NONE';
}

function RiskRing({ score }) {
  const color = score >= 80 ? '#ef4444' : score >= 50 ? '#f59e0b' : '#22c55e';
  const r = 12, circ = 2 * Math.PI * r;
  const pct = Math.min(score, 100) / 100;
  return (
    <div style={{ position:'relative', width:32, height:32 }}>
      <svg width={32} height={32} viewBox="0 0 32 32" style={{ transform:'rotate(-90deg)' }}>
        <circle cx={16} cy={16} r={r} fill="none" stroke="#1e2030" strokeWidth={3} />
        <circle cx={16} cy={16} r={r} fill="none" stroke={color} strokeWidth={3}
          strokeDasharray={`${pct * circ} ${circ}`} strokeLinecap="round"/>
      </svg>
      <span style={{
        position:'absolute', inset:0, display:'flex', alignItems:'center', justifyContent:'center',
        fontSize:9, fontWeight:700, color,
      }}>{score}</span>
    </div>
  );
}

function IncidentBubble({ count }) {
  const color = count >= 5 ? '#ef4444' : count >= 2 ? '#fb923c' : '#22c55e';
  const rgb = count >= 5 ? '239,68,68' : count >= 2 ? '251,146,60' : '34,197,94';
  return (
    <div style={{
      width:24, height:24, borderRadius:'50%',
      background: `rgba(${rgb},.15)`,
      border:`1px solid ${color}40`,
      display:'flex', alignItems:'center', justifyContent:'center',
      fontSize:10, fontWeight:700, color,
    }}>{count}</div>
  );
}

function ActionBadge({ action }) {
  const label = mapActionLabel(action);
  if (label === 'NONE') return <span style={{ color:'#5a5d75', fontSize:11 }}>NONE</span>;
  const styles = {
    DROP:         { bg:'rgba(239,68,68,.15)',   color:'#ef4444', border:'rgba(239,68,68,.3)' },
    'RATE-LIMIT': { bg:'rgba(59,130,246,.15)',  color:'#60a5fa', border:'rgba(59,130,246,.3)' },
    MONITOR:      { bg:'rgba(34,197,94,.12)',   color:'#4ade80', border:'rgba(34,197,94,.25)' },
    MONITORING:   { bg:'rgba(34,197,94,.12)',   color:'#4ade80', border:'rgba(34,197,94,.25)' },
    ISOLATED:     { bg:'rgba(168,85,247,.15)',  color:'#c084fc', border:'rgba(168,85,247,.3)' },
  };
  const s = styles[label] || { bg:'rgba(90,93,117,.12)', color:'#9ca3af', border:'rgba(90,93,117,.3)' };
  return (
    <span style={{
      fontSize:10, fontWeight:700, padding:'2px 8px', borderRadius:4, letterSpacing:.4,
      background:s.bg, color:s.color, border:`1px solid ${s.border}`,
    }}>{label}</span>
  );
}

const STATUS_LABEL_RO = {
  online: 'Online',
  alert: 'Țintă',
  warning: 'Atenție',
  blocked: 'Blocat',
  isolated: 'Izolat',
  offline: 'Offline',
};

function LegendSwatch({ color, label, desc }) {
  return (
    <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
      <div
        style={{
          width: 4,
          minHeight: 40,
          borderRadius: 2,
          background: color,
          flexShrink: 0,
          marginTop: 2,
        }}
      />
      <div>
        <div style={{ fontSize: 12, fontWeight: 700, color: '#e2e4f0' }}>{label}</div>
        <div style={{ fontSize: 11, color: '#8b8fa8', lineHeight: 1.45, marginTop: 2 }}>{desc}</div>
      </div>
    </div>
  );
}

export default function Devices({ devices, incidents, search }) {
  const [statusFilter, setStatusFilter] = useState('all');
  const [localSearch, setLocalSearch] = useState('');
  /** null | 'network' | device object */
  const [detailPanel, setDetailPanel] = useState(null);

  const q = (search || localSearch).toLowerCase();

  const victimDeviceIds = useMemo(() => {
    const s = new Set();
    (incidents || []).forEach((i) => {
      const v = i.dispozitiv_victima;
      if (v) s.add(v);
    });
    return s;
  }, [incidents]);

  const filtered = useMemo(() => {
    return (devices || []).filter(d => {
      const matchStatus = statusFilter === 'all' || d.status === statusFilter;
      const matchSearch = !q ||
        d.name?.toLowerCase().includes(q) ||
        d.ip?.includes(q) ||
        d.role?.toLowerCase().includes(q) ||
        d.device_id?.toLowerCase().includes(q);
      return matchStatus && matchSearch;
    });
  }, [devices, statusFilter, q]);

  const incidentsForDevice = (d) => {
    if (!d?.ip) return [];
    return (incidents || []).filter(
      (i) => i.sursa_ip === d.ip || i.dispozitiv_victima === d.device_id,
    ).slice(0, 8);
  };

  useEffect(() => {
    if (!detailPanel) return;
    const onKey = (e) => {
      if (e.key === 'Escape') setDetailPanel(null);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [detailPanel]);

  // Risk score calculat din status + incidente recente
  const riskScore = (d) => {
    if (d.device_id === 'external_attacker') {
      // Atacatorul extern — risk bazat pe câte incidente a cauzat
      const attackerIncidents = (incidents || []).filter(i => i.sursa_ip === d.ip).length;
      return Math.min(attackerIncidents * 15 + 30, 99);
    }
    if (d.status === 'blocked' || d.status === 'isolated') return 90 + Math.min(d.incidents_recent * 2, 9);
    if (d.status === 'alert')   return 70 + Math.min(d.incidents_recent * 5, 25);
    if (d.status === 'warning') return 50 + Math.min(d.incidents_recent * 5, 25);
    return Math.max(10, d.incidents_recent * 8);
  };

  const col = { fontSize:11, color:'#5a5d75', fontWeight:600, textTransform:'uppercase', letterSpacing:.5 };
  const cell = { padding:'14px 14px', verticalAlign:'middle', borderBottom:'1px solid #1a1b25' };

  return (
    <div className="page" style={{ display:'flex', flexDirection:'column', gap:16 }}>
      <div style={{ display:'flex', alignItems:'flex-end', justifyContent:'space-between', flexWrap:'wrap', gap:14 }}>
        <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
          <div style={{ display:'flex', alignItems:'baseline', flexWrap:'wrap', gap:12 }}>
            <h1 style={{ fontSize:20, fontWeight:700, color:'#e2e4f0', margin:0 }}>Inventar rețea</h1>
            <span style={{ fontSize:12, color:'#5a5d75' }}>
              {devices?.length || 0} {devices?.length === 1 ? 'host' : 'hosturi'}
            </span>
            <button
              type="button"
              onClick={() => setDetailPanel('network')}
              style={{
                display:'inline-flex', alignItems:'center', gap:6,
                fontSize:12, fontWeight:600, color:'#60a5fa',
                background:'rgba(59,130,246,.1)', border:'1px solid rgba(59,130,246,.28)',
                borderRadius:6, padding:'4px 10px', cursor:'pointer',
              }}
            >
              <Network size={14} strokeWidth={2} />
              Detalii rețea
            </button>
          </div>
        </div>

        <div style={{ display:'flex', gap:10, alignItems:'center', flexWrap:'wrap' }}>
          <div style={{ position:'relative' }}>
            <Search size={12} style={{ position:'absolute', left:9, top:'50%', transform:'translateY(-50%)', color:'#5a5d75' }} />
            <input
              value={localSearch} onChange={e => setLocalSearch(e.target.value)}
              placeholder="Nume, IP sau rol…"
              style={{
                padding:'6px 10px 6px 28px',
                background:'#13141b', border:'1px solid #22243a',
                borderRadius:6, color:'#e2e4f0', fontSize:12, outline:'none', width:220,
              }}
            />
          </div>

          <div style={{ display:'flex', gap:4, flexWrap:'wrap' }}>
            {['all', 'online', 'alert', 'blocked', 'isolated'].map(s => (
              <button key={s} onClick={() => setStatusFilter(s)} style={{
                padding:'5px 11px', borderRadius:5, fontSize:11, fontWeight:600,
                background: statusFilter === s ? '#d4a520' : '#1a1b25',
                color: statusFilter === s ? '#000' : '#8b8fa8',
                border: `1px solid ${statusFilter === s ? '#d4a520' : '#22243a'}`,
                textTransform:'capitalize',
                cursor:'pointer',
              }}>{s === 'all' ? 'Toate stările' : s}</button>
            ))}
          </div>
        </div>
      </div>

      <div className="card" style={{ overflow:'hidden' }}>
        <table style={{ width:'100%', borderCollapse:'collapse' }}>
          <thead>
            <tr style={{ borderBottom:'1px solid #22243a' }}>
              {[
                'Dispozitiv', 'Adresă IP', 'Rol', 'Stare', 'Scor risc', 'Evenimente', 'Acțiune curentă', 'Ultimul eveniment', '',
              ].map(h => (
                <th key={h} style={{ ...col, padding:'10px 14px', textAlign:'left', background:'#0f1016' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={9} style={{ textAlign:'center', padding:32, color:'#5a5d75', fontSize:12 }}>
                  Niciun dispozitiv nu corespunde filtrului
                </td>
              </tr>
            )}
            {filtered.map(d => {
              const IconComp = ICON_MAP[d.icon] || Server;
              const score = riskScore(d);
              const isAttacker = d.device_id === 'external_attacker';
              const isVictim = victimDeviceIds.has(d.device_id) && !isAttacker;

              const iconColor = (() => {
                if (isAttacker) return '#ef4444';
                if (isVictim || d.status === 'alert') return '#fb923c';
                return {
                  online:'#22c55e', alert:'#fb923c', warning:'#f59e0b',
                  blocked:'#f87171', isolated:'#c084fc', offline:'#6b7280',
                }[d.status] || '#8b8fa8';
              })();

              const rgbFromHex = (hex) => {
                const h = hex.replace('#', '');
                const n = parseInt(h, 16);
                return `${(n >> 16) & 255},${(n >> 8) & 255},${n & 255}`;
              };

              const rowAccent = isAttacker
                ? '3px solid #dc2626'
                : isVictim
                  ? '3px solid #ea580c'
                  : undefined;

              const statusLabel = STATUS_LABEL_RO[d.status] || (d.status || '').toUpperCase();

              return (
                <tr
                  key={d.device_id}
                  style={{ transition:'background .1s' }}
                  onMouseEnter={e => { e.currentTarget.style.background = '#1a1b25'; }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
                >
                  <td style={{ ...cell, borderLeft: rowAccent || '3px solid transparent' }}>
                    <div style={{ display:'flex', alignItems:'center', gap:10 }}>
                      <div style={{
                        width:32, height:32, borderRadius:8,
                        background: `rgba(${rgbFromHex(iconColor)},.14)`,
                        display:'flex', alignItems:'center', justifyContent:'center',
                        border:`1px solid ${iconColor}45`,
                      }}>
                        <IconComp size={15} color={iconColor} strokeWidth={1.8} />
                      </div>
                      <div>
                        <div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap' }}>
                          <span style={{ fontSize:12, fontWeight:600, color:'#e2e4f0' }}>{d.name}</span>
                          {isAttacker && (
                            <span style={{
                              fontSize:9, fontWeight:700, letterSpacing:0.4,
                              color:'#f87171', border:'1px solid rgba(239,68,68,.4)',
                              background:'rgba(239,68,68,.12)', padding:'1px 6px', borderRadius:4,
                            }}>Sursă atac</span>
                          )}
                          {isVictim && (
                            <span style={{
                              fontSize:9, fontWeight:700, letterSpacing:0.4,
                              color:'#fb923c', border:'1px solid rgba(249,115,22,.4)',
                              background:'rgba(249,115,22,.1)', padding:'1px 6px', borderRadius:4,
                            }}>Țintă</span>
                          )}
                        </div>
                        <div style={{ fontSize:10, color:'#5a5d75' }}>{d.device_id}</div>
                      </div>
                    </div>
                  </td>

                  {/* IP */}
                  <td style={cell}>
                    <span style={{ fontSize:11, color:'#8b8fa8', fontFamily:'monospace' }}>{d.ip}</span>
                  </td>

                  {/* Role */}
                  <td style={cell}>
                    <span style={{ fontSize:11, color:'#8b8fa8' }}>{d.role}</span>
                  </td>

                  <td style={cell}>
                    {isAttacker && d.status === 'online' ? (
                      <span className="status-attacker" title="Host folosit ca sursă a traficului malițios în simulare">
                        Activ · atacator
                      </span>
                    ) : (
                      <span className={`status-${d.status}`}>{statusLabel}</span>
                    )}
                  </td>

                  {/* Risk Score */}
                  <td style={cell}>
                    <RiskRing score={score} />
                  </td>

                  {/* Incidents */}
                  <td style={cell}>
                    <IncidentBubble count={d.incidents_recent || 0} />
                  </td>

                  {/* Current Action */}
                  <td style={cell}>
                    <ActionBadge action={d.current_action} />
                  </td>

                  {/* Last Incident */}
                  <td style={cell}>
                    <span style={{ fontSize:10, color:'#5a5d75', fontFamily:'monospace' }}>
                      {d.last_incident || '—'}
                    </span>
                  </td>

                  {/* View */}
                  <td style={cell}>
                    <button
                      type="button"
                      onClick={() => setDetailPanel(d)}
                      style={{
                        fontSize:11, color:'#60a5fa', fontWeight:600,
                        display:'flex', alignItems:'center', gap:4,
                        padding:'4px 8px', borderRadius:5,
                        background:'rgba(59,130,246,.08)',
                        border:'1px solid rgba(59,130,246,.2)',
                        cursor:'pointer',
                      }}
                    >
                      <ExternalLink size={11} /> Detalii
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {detailPanel && (
        <div
          role="presentation"
          style={{
            position:'fixed', inset:0, zIndex:200,
            background:'rgba(6,7,12,.72)',
            backdropFilter:'blur(6px)',
            display:'flex', alignItems:'center', justifyContent:'center',
            padding:20,
          }}
          onClick={() => setDetailPanel(null)}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="devices-panel-title"
            className="card"
            style={{
              width:'100%', maxWidth: detailPanel === 'network' ? 480 : 420,
              maxHeight:'min(88vh, 640px)', overflowY:'auto',
              padding:'20px 22px', position:'relative',
              border:'1px solid rgba(42,45,69,.9)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <button
              type="button"
              aria-label="Închide"
              onClick={() => setDetailPanel(null)}
              style={{
                position:'absolute', top:14, right:14,
                padding:6, borderRadius:6, color:'#8b8fa8',
                background:'rgba(255,255,255,.04)', border:'1px solid #2a2d45',
                cursor:'pointer', display:'flex',
              }}
            >
              <X size={18} />
            </button>

            {detailPanel === 'network' ? (
              <>
                <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:14, paddingRight:36 }}>
                  <div style={{
                    width:36, height:36, borderRadius:8,
                    background:'rgba(59,130,246,.12)', border:'1px solid rgba(59,130,246,.25)',
                    display:'flex', alignItems:'center', justifyContent:'center',
                  }}>
                    <Network size={18} color="#60a5fa" />
                  </div>
                  <div>
                    <h2 id="devices-panel-title" style={{ fontSize:15, fontWeight:700, color:'#e2e4f0', margin:0 }}>
                      Context rețea (laborator)
                    </h2>
                    <p style={{ fontSize:11, color:'#5a5d75', margin:'4px 0 0' }}>
                      Cum se citește inventarul și legătura cu răspunsul automat
                    </p>
                  </div>
                </div>

                <p style={{ fontSize:12, color:'#a1a7bb', lineHeight:1.6, marginBottom:16 }}>
                  Tabelul reflectă hosturile din topologia proiectului (rețea izolată Docker, ex. segment{' '}
                  <span style={{ fontFamily:'ui-monospace', color:'#7dd3fc' }}>172.20.0.0/24</span>
                  ). Nu este un inventar „magazin”: starea și acțiunile provin din <strong style={{ color:'#e2e4f0' }}>incidente consemnate</strong> și din <strong style={{ color:'#e2e4f0' }}>reguli aplicate pe gateway</strong> (iptables — DROP, rate-limit, izolare).
                </p>

                <div style={{ fontSize:11, fontWeight:700, color:'#9ca3b8', marginBottom:10, textTransform:'uppercase', letterSpacing:0.6 }}>
                  Semnificația chenarelor
                </div>
                <div style={{ display:'flex', flexDirection:'column', gap:14, marginBottom:18 }}>
                  <LegendSwatch
                    color="#dc2626"
                    label="Sursă de atac"
                    desc="Host marcat ca origine a traficului malițios în simulare (ex. atacator extern). Nu înseamnă automat că e „oprit” — verifică coloana Stare și Acțiune curentă."
                  />
                  <LegendSwatch
                    color="#ea580c"
                    label="Țintă"
                    desc="A apărut ca victimă (dispozitiv vizat) într-un incident. Portocaliul îl deosebește vizual de sursa de atac."
                  />
                </div>

                <div style={{ fontSize:11, fontWeight:700, color:'#9ca3b8', marginBottom:8, textTransform:'uppercase', letterSpacing:0.6 }}>
                  Coloane utile
                </div>
                <ul style={{ margin:0, paddingLeft:18, fontSize:12, color:'#8b8fa8', lineHeight:1.55 }}>
                  <li><strong style={{ color:'#cbd5e1' }}>Evenimente</strong> — incidente recente în care apare IP-ul ca sursă.</li>
                  <li><strong style={{ color:'#cbd5e1' }}>Acțiune curentă</strong> — ce aplică IDPS-ul pe firewall pentru acest flux sau container.</li>
                  <li><strong style={{ color:'#cbd5e1' }}>Ultimul eveniment</strong> — ID-ul celui mai recent incident legat de host.</li>
                </ul>
              </>
            ) : (
              <>
                {(() => {
                  const d = detailPanel;
                  const related = incidentsForDevice(d);
                  const isAttacker = d.device_id === 'external_attacker';
                  const isVictim = victimDeviceIds.has(d.device_id) && !isAttacker;
                  return (
                    <>
                      <h2 id="devices-panel-title" style={{ fontSize:15, fontWeight:700, color:'#e2e4f0', margin:'0 0 6px', paddingRight:36 }}>
                        {d.name}
                      </h2>
                      <div style={{ fontSize:11, color:'#5a5d75', fontFamily:'ui-monospace', marginBottom:14 }}>
                        {d.ip} · {d.device_id}
                      </div>
                      <div style={{ fontSize:12, color:'#8b8fa8', lineHeight:1.5, marginBottom:14 }}>
                        {d.role}
                      </div>
                      <div style={{ display:'flex', flexWrap:'wrap', gap:8, marginBottom:16 }}>
                        {isAttacker && (
                          <span style={{
                            fontSize:10, fontWeight:700, color:'#f87171',
                            border:'1px solid rgba(239,68,68,.35)', background:'rgba(239,68,68,.1)',
                            padding:'3px 8px', borderRadius:4,
                          }}>Sursă atac</span>
                        )}
                        {isVictim && (
                          <span style={{
                            fontSize:10, fontWeight:700, color:'#fb923c',
                            border:'1px solid rgba(249,115,22,.35)', background:'rgba(249,115,22,.08)',
                            padding:'3px 8px', borderRadius:4,
                          }}>Țintă</span>
                        )}
                        <span className={`status-${d.status}`} style={{ fontSize:10 }}>
                          {STATUS_LABEL_RO[d.status] || d.status}
                        </span>
                      </div>
                      <div style={{ fontSize:11, fontWeight:700, color:'#9ca3b8', marginBottom:8 }}>
                        Evenimente asociate ({related.length}{related.length >= 8 ? '+' : ''})
                      </div>
                      {related.length === 0 ? (
                        <p style={{ fontSize:12, color:'#5a5d75', margin:0 }}>Niciun incident listat pentru acest host în setul curent.</p>
                      ) : (
                        <ul style={{ margin:0, padding:0, listStyle:'none', display:'flex', flexDirection:'column', gap:8 }}>
                          {related.map((inc) => (
                            <li
                              key={inc.id}
                              style={{
                                fontSize:11, padding:'8px 10px',
                                background:'#0f1016', borderRadius:8,
                                border:'1px solid #252838',
                                fontFamily:'ui-monospace', color:'#a1a7bb',
                              }}
                            >
                              <span style={{ color:'#7dd3fc' }}>{inc.id}</span>
                              {' · '}
                              {inc.dispozitiv_victima === d.device_id ? (
                                <span style={{ color:'#fb923c' }}>țintă</span>
                              ) : (
                                <span style={{ color:'#f87171' }}>sursă</span>
                              )}
                              {' · '}
                              {inc.severitate || '—'}
                            </li>
                          ))}
                        </ul>
                      )}
                    </>
                  );
                })()}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}