import { useState, useMemo } from 'react';
import {
  AlertTriangle, CheckCircle, Shield, Clock, ChevronDown, ChevronUp,
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, ResponsiveContainer, Tooltip,
} from 'recharts';

function mapDecizieLabel(decizie) {
  const map = {
    drop: 'DROP',
    rate_limit_agresiv: 'RATE-LIMIT',
    rate_limit_permisiv: 'RATE-LIMIT',
    log_only: 'MONITOR',
  };
  return map[decizie] || decizie?.toUpperCase() || '—';
}

const decizieColor = {
  drop: '#ef4444',
  rate_limit_agresiv: '#60a5fa',
  rate_limit_permisiv: '#f59e0b',
  log_only: '#4ade80',
};

function mapStatus(status) {
  const map = {
    active: { label: 'Activ', color: '#ef4444' },
    expired: { label: 'Expirat', color: '#6b7280' },
    logged: { label: 'Înregistrat', color: '#6b7280' },
    ai_unblocked: { label: 'Deblocat', color: '#22c55e' },
  };
  return map[status] || { label: status, color: '#6b7280' };
}

/** Backend poate trimite HIGH sau high — normalizăm pentru badge */
function normalizeSeveritate(s) {
  if (!s) return 'LOW';
  const u = String(s).toUpperCase();
  if (['HIGH', 'MEDIUM', 'LOW', 'LOG_ONLY'].includes(u)) return u;
  return u;
}

function MiniStat({ icon: Icon, value, label, color }) {
  return (
    <div className="card" style={{ padding: '14px 16px', flex: 1, minWidth: 0 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 8 }}>
        <Icon size={18} color={color} strokeWidth={1.8} />
      </div>
      <div style={{ fontSize: 26, fontWeight: 700, color, lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 11, color: '#8b8fa8', marginTop: 4 }}>{label}</div>
    </div>
  );
}

/** Istoric pe ore (24h): volum, acțiuni aplicate, severitate ridicată */
function genIncidentBuckets(incidents, hours = 24) {
  const now = Date.now();
  const buckets = Array.from({ length: hours }, (_, i) => ({
    t: `${String(hours - 1 - i).padStart(2, '0')}h`,
    count: 0,
    withAction: 0,
    highCount: 0,
  }));

  (incidents || []).forEach((inc) => {
    const ts = new Date(inc.timestamp).getTime();
    if (Number.isNaN(ts)) return;
    const ageMs = now - ts;
    const hr = Math.floor(ageMs / 3600000);
    if (hr >= 0 && hr < hours) {
      const idx = hours - 1 - hr;
      buckets[idx].count += 1;
      if (inc.decizie === 'drop' || String(inc.decizie || '').includes('rate_limit')) {
        buckets[idx].withAction += 1;
      }
      if (normalizeSeveritate(inc.severitate) === 'HIGH') {
        buckets[idx].highCount += 1;
      }
    }
  });
  return buckets;
}

function MiniAreaChart({ data, dataKey, name, stroke, gradientId, fillOpacity = 0.22 }) {
  return (
    <ResponsiveContainer width="100%" height={88}>
      <AreaChart data={data}>
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={stroke} stopOpacity={fillOpacity} />
            <stop offset="95%" stopColor={stroke} stopOpacity={0} />
          </linearGradient>
        </defs>
        <XAxis dataKey="t" tick={{ fill: '#5a5d75', fontSize: 8 }} interval={4} axisLine={false} tickLine={false} />
        <YAxis hide />
        <Tooltip content={<ChartTooltip />} />
        <Area
          type="monotone"
          dataKey={dataKey}
          name={name}
          stroke={stroke}
          strokeWidth={1.4}
          fill={`url(#${gradientId})`}
          dot={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

const ChartTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div
      style={{
        background: '#1a1b25',
        border: '1px solid #2a2d45',
        borderRadius: 6,
        padding: '8px 10px',
        fontSize: 11,
      }}
    >
      <div style={{ color: '#8b8fa8', marginBottom: 4 }}>{label}</div>
      {payload.map((p) => (
        <div key={p.dataKey} style={{ color: '#e2e4f0' }}>
          {p.name}: <strong>{p.value}</strong>
        </div>
      ))}
    </div>
  );
};

function formatTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString('ro-RO', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDuration(secs) {
  if (!secs || secs <= 0) return '—';
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

function incidentTitle(inc) {
  if (inc.ai_verdict?.tip_atac) return inc.ai_verdict.tip_atac;
  if (inc.severitate === 'LOG_ONLY' || inc.decizie === 'log_only') {
    return 'Anomalie (doar jurnal)';
  }
  return `Incident ECOD (raport ${inc.ratio != null ? `${Number(inc.ratio).toFixed(1)}×` : '—'})`;
}

export default function Incidents({ stats, incidents, search }) {
  const [expanded, setExpanded] = useState(null);

  const filtered = useMemo(() => {
    if (!search) return incidents || [];
    const s = search.toLowerCase();
    return (incidents || []).filter(
      (i) =>
        i.id?.toLowerCase().includes(s) ||
        i.sursa_ip?.includes(s) ||
        i.ai_verdict?.tip_atac?.toLowerCase().includes(s) ||
        i.dispozitiv_victima?.toLowerCase().includes(s),
    );
  }, [incidents, search]);

  const chartData = useMemo(() => genIncidentBuckets(incidents), [incidents]);

  const list = incidents || [];
  const active = list.filter((i) => i.status === 'active').length;
  const critical = list.filter((i) => normalizeSeveritate(i.severitate) === 'HIGH').length;
  const healthy = stats?.healthy_nodes ?? '—';

  const sevColor = {
    HIGH: '#ef4444',
    MEDIUM: '#f59e0b',
    LOW: '#60a5fa',
    LOG_ONLY: '#38bdf8',
  };

  return (
    <div className="page" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <MiniStat icon={AlertTriangle} value={active} label="Incidente active" color="#ef4444" />
        <MiniStat icon={AlertTriangle} value={critical} label="Severitate ridicată" color="#f59e0b" />
        <MiniStat icon={CheckCircle} value={healthy} label="Noduri în regulă" color="#22c55e" />
        <MiniStat
          icon={Shield}
          value={stats?.avg_ai_response ? `${stats.avg_ai_response}s` : '—'}
          label="Timp mediu analiză"
          color="#94a3b8"
        />
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: 12,
        }}
      >
        <div className="card" style={{ padding: '12px 14px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#9ca3b8', marginBottom: 4 }}>
            Volum / oră
          </div>
          <div style={{ fontSize: 9, color: '#5a5d75', marginBottom: 6 }}>Toate incidentele (24h)</div>
          <MiniAreaChart
            data={chartData}
            dataKey="count"
            name="Total"
            stroke="#ef4444"
            gradientId="incVol"
          />
        </div>
        <div className="card" style={{ padding: '12px 14px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#9ca3b8', marginBottom: 4 }}>
            Acțiuni aplicate
          </div>
          <div style={{ fontSize: 9, color: '#5a5d75', marginBottom: 6 }}>DROP / rate-limit</div>
          <MiniAreaChart
            data={chartData}
            dataKey="withAction"
            name="Cu acțiune"
            stroke="#60a5fa"
            gradientId="incAct"
          />
        </div>
        <div className="card" style={{ padding: '12px 14px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#9ca3b8', marginBottom: 4 }}>
            Severitate ridicată
          </div>
          <div style={{ fontSize: 9, color: '#5a5d75', marginBottom: 6 }}>HIGH / oră</div>
          <MiniAreaChart
            data={chartData}
            dataKey="highCount"
            name="HIGH"
            stroke="#f59e0b"
            gradientId="incHigh"
          />
        </div>
      </div>

      <div
        className="card"
        style={{
          padding: '14px 16px',
          display: 'flex',
          flexDirection: 'column',
          gap: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 2, flexWrap: 'wrap', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertTriangle size={14} color="#ca8a04" />
            <span style={{ fontSize: 13, fontWeight: 700, color: '#e2e4f0' }}>Incidente</span>
            <span style={{ fontSize: 11, color: '#5a5d75' }}>{filtered.length} în listă</span>
          </div>
          <span style={{ fontSize: 11, color: '#5a5d75', display: 'flex', alignItems: 'center', gap: 5 }}>
            <Clock size={11} /> Toate înregistrările
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {filtered.length === 0 && (
            <div style={{ color: '#5a5d75', textAlign: 'center', paddingTop: 24, fontSize: 12 }}>
              Nu există incidente care să corespundă filtrului.
            </div>
          )}

          {filtered.map((inc, rowIdx) => {
            const rowKey = inc.id ?? `${inc.timestamp || ''}-${rowIdx}`;
            const isOpen = expanded === rowKey;
            const sev = normalizeSeveritate(inc.severitate);
            const sc = sevColor[sev] || '#8b8fa8';
            const { label: statusLabel, color: statusColor } = mapStatus(inc.status);
            const tipAtac = incidentTitle(inc);
            const decLabel = mapDecizieLabel(inc.decizie);
            const badgeClass = sev === 'LOG_ONLY' ? 'LOG_ONLY' : sev;

            const detailFields = [
              { label: 'Oră', value: formatTime(inc.timestamp), wide: false },
              { label: 'Sursă IP', value: inc.sursa_ip || '—', wide: false, mono: true },
              {
                label: 'Țintă',
                value: inc.dispozitiv_victima?.replace(/_/g, ' ') || '—',
                wide: true,
              },
              {
                label: 'MITRE',
                value: inc.ai_verdict?.mitre_ids?.[0] || '—',
                color: '#7dd3fc',
                mono: true,
              },
              { label: 'Acțiune', value: decLabel, color: decizieColor[inc.decizie] || '#e2e4f0' },
            ];

            return (
              <div
                key={rowKey}
                style={{
                  border: '1px solid #252838',
                  borderLeft: `3px solid ${sc}`,
                  borderRadius: 10,
                  background: '#14151c',
                  color: '#e2e4f0',
                }}
              >
                <div
                  style={{ padding: '12px 14px', cursor: 'pointer', color: '#e2e4f0' }}
                  onClick={() => setExpanded(isOpen ? null : rowKey)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setExpanded(isOpen ? null : rowKey);
                    }
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      justifyContent: 'space-between',
                      gap: 10,
                      flexWrap: 'wrap',
                      marginBottom: 10,
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        alignItems: 'center',
                        gap: 8,
                        flex: '1 1 200px',
                        minWidth: 200,
                        maxWidth: '100%',
                      }}
                    >
                      <span style={{ fontSize: 10, color: '#64748b', fontFamily: 'ui-monospace, monospace' }}>{inc.id}</span>
                      <span className={`badge badge-${badgeClass}`}>
                        {sev === 'LOG_ONLY' ? 'LOG' : sev}
                      </span>
                      <span
                        style={{
                          fontSize: 13,
                          fontWeight: 600,
                          color: '#e8e9ef',
                          lineHeight: 1.35,
                          minWidth: 140,
                        }}
                      >
                        {tipAtac}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                      <span
                        style={{
                          fontSize: 10,
                          fontWeight: 700,
                          padding: '4px 10px',
                          borderRadius: 999,
                          background: `${statusColor}18`,
                          color: statusColor,
                          border: `1px solid ${statusColor}45`,
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {statusLabel}
                      </span>
                      {isOpen ? <ChevronUp size={16} color="#64748b" /> : <ChevronDown size={16} color="#64748b" />}
                    </div>
                  </div>

                  {/* flex-wrap în loc de grid 5 coloane — evită „doar buline” pe ecrane înguste */}
                  <div
                    style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: '10px 20px',
                      alignItems: 'flex-start',
                    }}
                  >
                    {detailFields.map(({ label, value, color: c, wide, mono }) => (
                      <div
                        key={label}
                        style={{
                          minWidth: wide ? 200 : 100,
                          maxWidth: wide ? '100%' : 160,
                          flex: wide ? '1 1 200px' : '0 1 auto',
                        }}
                      >
                        <div
                          style={{
                            fontSize: 9,
                            color: '#64748b',
                            marginBottom: 3,
                            textTransform: 'uppercase',
                            letterSpacing: 0.6,
                          }}
                        >
                          {label}
                        </div>
                        <div
                          style={{
                            fontSize: 12,
                            fontWeight: 600,
                            color: c || '#e2e4f0',
                            fontFamily: mono ? 'ui-monospace, monospace' : 'inherit',
                            wordBreak: 'break-all',
                          }}
                        >
                          {value}
                        </div>
                      </div>
                    ))}
                  </div>

                  {(inc.anomalii_fereastra > 0 || inc.timer_secunde > 0 || inc.scor_ecod > 0) && (
                    <div
                      style={{
                        marginTop: 10,
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: '8px 16px',
                        fontSize: 11,
                        color: '#64748b',
                      }}
                    >
                      {inc.anomalii_fereastra > 0 && (
                        <span>
                          Fereastră:{' '}
                          <strong style={{ color: '#cbd5e1' }}>{inc.anomalii_fereastra}</strong>
                        </span>
                      )}
                      {inc.timer_secunde > 0 && (
                        <span>
                          Timer:{' '}
                          <strong style={{ color: '#cbd5e1' }}>{formatDuration(inc.timer_secunde)}</strong>
                        </span>
                      )}
                      {inc.scor_ecod > 0 && (
                        <span>
                          Scor ECOD:{' '}
                          <strong style={{ color: '#cbd5e1' }}>{inc.scor_ecod}</strong>
                        </span>
                      )}
                      {inc.ratio > 0 && (
                        <span>
                          Raport:{' '}
                          <strong style={{ color: inc.ratio >= 3 ? '#ef4444' : '#f59e0b' }}>
                            {inc.ratio}×
                          </strong>
                        </span>
                      )}
                    </div>
                  )}
                </div>

                {isOpen && (
                  <div
                    style={{
                      padding: '12px 14px 14px',
                      borderTop: '1px solid #252838',
                      background: '#0f1016',
                    }}
                  >
                    {inc.ai_verdict ? (
                      <>
                        <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600, marginBottom: 10 }}>
                          Detalii analiză automată
                        </div>
                        <div
                          style={{
                            display: 'grid',
                            gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
                            gap: 12,
                            marginBottom: 12,
                          }}
                        >
                          <div>
                            <div style={{ fontSize: 10, color: '#64748b', marginBottom: 3 }}>Tip</div>
                            <div style={{ fontSize: 12, color: '#e2e4f0' }}>{inc.ai_verdict.tip_atac || '—'}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: 10, color: '#64748b', marginBottom: 3 }}>Clasificare</div>
                            <div style={{ fontSize: 12, color: '#e2e4f0' }}>{inc.ai_verdict.severitate || '—'}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: 10, color: '#64748b', marginBottom: 3 }}>Încredere</div>
                            <div style={{ fontSize: 12, color: '#86efac', fontWeight: 700 }}>
                              {inc.ai_verdict.confidence != null
                                ? `${Math.round(inc.ai_verdict.confidence * 100)}%`
                                : '—'}
                            </div>
                          </div>
                        </div>

                        {inc.abuseipdb && (
                          <div
                            style={{
                              display: 'flex',
                              flexWrap: 'wrap',
                              gap: '12px 20px',
                              marginBottom: 10,
                              fontSize: 11,
                            }}
                          >
                            <span style={{ color: '#64748b' }}>
                              AbuseIPDB:{' '}
                              <strong
                                style={{
                                  color: inc.abuseipdb.score >= 75 ? '#ef4444' : '#f59e0b',
                                }}
                              >
                                {inc.abuseipdb.score >= 0 ? inc.abuseipdb.score : 'N/A'}
                              </strong>
                            </span>
                            {inc.abuseipdb.isp && (
                              <span style={{ color: '#64748b' }}>
                                ISP: <strong style={{ color: '#e2e4f0' }}>{inc.abuseipdb.isp}</strong>
                              </span>
                            )}
                            {inc.whois?.organization && (
                              <span style={{ color: '#64748b' }}>
                                Org: <strong style={{ color: '#e2e4f0' }}>{inc.whois.organization}</strong>
                              </span>
                            )}
                          </div>
                        )}

                        {inc.ai_verdict.explicatie && (
                          <div style={{ fontSize: 12, color: '#a1a7bb', lineHeight: 1.65, marginBottom: 10 }}>
                            {inc.ai_verdict.explicatie}
                          </div>
                        )}

                        {inc.ai_verdict.recomandari?.length > 0 && (
                          <div>
                            <div style={{ fontSize: 10, color: '#64748b', marginBottom: 6 }}>Recomandări</div>
                            <ul style={{ margin: 0, paddingLeft: 18, color: '#a1a7bb', fontSize: 12, lineHeight: 1.6 }}>
                              {inc.ai_verdict.recomandari.map((rec, i) => (
                                <li key={i} style={{ marginBottom: 4 }}>
                                  {rec}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {inc.ai_elapsed_seconds != null && (
                          <div style={{ marginTop: 10, fontSize: 10, color: '#64748b' }}>
                            Durată analiză: {Number(inc.ai_elapsed_seconds).toFixed(1)}s
                          </div>
                        )}
                      </>
                    ) : (
                      <div style={{ fontSize: 12, color: '#64748b' }}>
                        Fără analiză automată pentru acest eveniment (ex. doar jurnal / prag neatinse).
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
