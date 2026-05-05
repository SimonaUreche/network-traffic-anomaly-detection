import { useMemo, useState } from 'react';

/* Poziții de bază — gateway centru, fără atacator (se adaugă dinamic) */
const BASE_POSITIONS = {
  gateway:      { x: 50, y: 52 },
  smart_plug:   { x: 30, y: 15 },
  iot_sensor:   { x: 70, y: 15 },
  smart_camera: { x: 15, y: 55 },
  web_server:   { x: 30, y: 88 },
  auth_server:  { x: 70, y: 88 },
  dns_server:   { x: 88, y: 55 },
};

const EXTERNAL_ATTACKER_POS = { x: 8, y: 24 };

const STATUS_COLOR = {
  online:   '#22c55e',
  alert:    '#ef4444',
  warning:  '#f59e0b',
  blocked:  '#ef4444',
  isolated: '#a855f7',
  offline:  '#6b7280',
};

function DeviceIcon({ type, size = 14 }) {
  const s = { fill:'none', stroke:'currentColor', strokeWidth:'2', strokeLinecap:'round', strokeLinejoin:'round' };
  const icons = {
    router: <svg width={size} height={size} viewBox="0 0 24 24" {...s}><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="14" x2="6" y2="11"/><line x1="12" y1="14" x2="12" y2="11"/><line x1="18" y1="14" x2="18" y2="11"/><path d="M2 11h20"/><circle cx="6" cy="18" r="1" fill="currentColor" stroke="none"/></svg>,
    server: <svg width={size} height={size} viewBox="0 0 24 24" {...s}><rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><circle cx="7" cy="7" r="1" fill="currentColor" stroke="none"/><circle cx="7" cy="17" r="1" fill="currentColor" stroke="none"/></svg>,
    thermometer: <svg width={size} height={size} viewBox="0 0 24 24" {...s}><path d="M14 14.76V3.5a2.5 2.5 0 0 0-5 0v11.26a4.5 4.5 0 1 0 5 0z"/></svg>,
    lock: <svg width={size} height={size} viewBox="0 0 24 24" {...s}><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
    camera: <svg width={size} height={size} viewBox="0 0 24 24" {...s}><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>,
    plug: <svg width={size} height={size} viewBox="0 0 24 24" {...s}><path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8H6a2 2 0 0 0-2 2v3a6 6 0 0 0 12 0v-3a2 2 0 0 0-2-2z"/></svg>,
    globe: <svg width={size} height={size} viewBox="0 0 24 24" {...s}><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>,
    'alert-triangle': <svg width={size} height={size} viewBox="0 0 24 24" {...{...s, strokeWidth:'2.5'}}><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  };
  return icons[type] || icons.server;
}

function buildIpToDeviceId(devices) {
  const m = {};
  (devices || []).forEach(d => {
    if (d.ip && d.device_id) m[d.ip] = d.device_id;
  });
  return m;
}

function resolveAttackerId(incident, ipToId) {
  if (!incident) return null;
  const ip = incident.sursa_ip;
  if (incident.sursa_tip === 'extern' || ip === '172.20.0.99') return 'external_attacker';
  if (ip && ipToId[ip]) return ipToId[ip];
  return null;
}

function resolveVictimId(incident) {
  if (!incident) return null;
  return incident.dispozitiv_victima || incident.container_victima || null;
}

export default function NetworkTopology({ devices, activeIncident }) {
  const [tooltip, setTooltip] = useState(null);

  const deviceMap = useMemo(() => {
    const m = {};
    (devices || []).forEach(d => { m[d.device_id] = d; });
    return m;
  }, [devices]);

  const ipToId = useMemo(() => buildIpToDeviceId(devices), [devices]);

  const { nodePositions, attackerId, victimId, showAttackVector } = useMemo(() => {
    const positions = { ...BASE_POSITIONS };
    const att = resolveAttackerId(activeIncident, ipToId);
    const vic = resolveVictimId(activeIncident);

    const active = activeIncident && (activeIncident.status === 'active' || activeIncident.status === 'logged');

    if (att === 'external_attacker') {
      positions.external_attacker = { ...EXTERNAL_ATTACKER_POS };
    }

    return {
      nodePositions: positions,
      attackerId: active ? att : null,
      victimId: active ? vic : null,
      showAttackVector: !!(active && att && vic && positions[att] && positions[vic] && att !== vic),
    };
  }, [activeIncident, ipToId]);

  const edges = useMemo(() => {
    return Object.keys(nodePositions)
      .filter(k => k !== 'gateway')
      .map(k => ({
        from: k,
        to: 'gateway',
        key: `g-${k}`,
      }));
  }, [nodePositions]);

  return (
    <div style={{ position:'relative', width:'100%', height:'100%', minHeight:320 }}>
      <svg viewBox="0 0 100 100" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
        <defs>
          <filter id="glow-green" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="1" result="blur"/>
            <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
          <filter id="glow-red" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="1.6" result="blur"/>
            <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
          <marker id="arrow-attack" markerWidth="5" markerHeight="5" refX="4" refY="2.5" orient="auto">
            <path d="M0,0 L5,2.5 L0,5 Z" fill="#ef4444" opacity="0.85"/>
          </marker>
        </defs>

        {/* Legături normale spre gateway (victimă în alertă: linie discretă roșie spre hub) */}
        {edges.map(({ from, to, key }) => {
          const a = nodePositions[from], b = nodePositions[to];
          if (!a || !b) return null;
          const dev = deviceMap[from];
          const isVictim = victimId === from;
          const isUnderAttack = showAttackVector && (from === victimId || from === attackerId);
          const muted = showAttackVector && (from === attackerId || from === victimId);
          return (
            <line key={key}
              x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke={
                isUnderAttack ? 'rgba(239,68,68,0.35)' : '#2a2d42'
              }
              strokeWidth={isVictim ? 0.45 : 0.32}
              strokeDasharray={muted && from === attackerId ? '1.2 0.8' : undefined}
              opacity={muted ? 0.85 : 1}
            />
          );
        })}

        {/* Vector atac: atacator → victimă (vizibil ca în mockup) */}
        {showAttackVector && (
          <line
            x1={nodePositions[attackerId].x}
            y1={nodePositions[attackerId].y}
            x2={nodePositions[victimId].x}
            y2={nodePositions[victimId].y}
            stroke="#ef4444"
            strokeWidth={0.85}
            strokeDasharray="2.2 1.1"
            markerEnd="url(#arrow-attack)"
            opacity={0.92}
          />
        )}

        {Object.entries(nodePositions).map(([id, pos]) => {
          const dev = deviceMap[id];
          const status = dev?.status || 'offline';
          const isAttackerNode = attackerId === id;
          const isVictimNode = victimId === id;
          const highlightAttack = isAttackerNode || isVictimNode;

          let color = STATUS_COLOR[status] || '#6b7280';
          if (isAttackerNode) color = '#ef4444';
          else if (isVictimNode && showAttackVector) color = '#f87171';

          const isGateway = id === 'gateway';
          const isExternal = id === 'external_attacker';
          const r = isGateway ? 6.2 : isExternal ? 5.2 : 4.8;

          return (
            <g key={id} style={{ cursor:'pointer' }}
              onMouseEnter={() => setTooltip({ id, dev, pos })}
              onMouseLeave={() => setTooltip(null)}
            >
              <circle cx={pos.x} cy={pos.y} r={r + (highlightAttack ? 2.4 : 2)}
                fill="none" stroke={color} strokeWidth={highlightAttack ? 0.45 : 0.28}
                opacity={highlightAttack ? 0.55 : 0.22}/>

              <circle cx={pos.x} cy={pos.y} r={r}
                fill={isAttackerNode ? '#1f0a0c' : '#14151c'}
                stroke={color}
                strokeWidth={highlightAttack ? 1.05 : isGateway ? 0.95 : 0.65}
                filter={
                  highlightAttack ? 'url(#glow-red)' :
                  status === 'online' ? 'url(#glow-green)' : undefined
                }
              />

              <circle cx={pos.x + r * 0.58} cy={pos.y - r * 0.58} r={1.05}
                fill={color} stroke="#0a0b0f" strokeWidth={0.35}/>

              <foreignObject
                x={pos.x - (isGateway ? 5.2 : 4)}
                y={pos.y - (isGateway ? 5.2 : 4)}
                width={isGateway ? 10.4 : 8}
                height={isGateway ? 10.4 : 8}
              >
                <div style={{
                  width:'100%', height:'100%',
                  display:'flex', alignItems:'center', justifyContent:'center',
                  color,
                }}>
                  <DeviceIcon type={dev?.icon || 'server'} size={isGateway ? 8.5 : 6.5} />
                </div>
              </foreignObject>

              <text x={pos.x} y={pos.y + r + 4} textAnchor="middle"
                fontSize={2.95} fill={isAttackerNode ? '#fca5a5' : '#9ca3b8'}
                fontWeight={isAttackerNode || isVictimNode ? 650 : 400}>
                {isExternal ? 'external attacker' : (dev?.name || id).replace(/_/g, ' ')}
              </text>

              <text x={pos.x} y={pos.y + r + 6.8} textAnchor="middle"
                fontSize={2.35} fill="#6b7280">
                {dev?.ip || ''}
              </text>
            </g>
          );
        })}
      </svg>

      {tooltip?.dev && (
        <div style={{
          position:'absolute', zIndex:10, pointerEvents:'none',
          left: `${Math.min(tooltip.pos.x + 6, 60)}%`,
          top:  `${Math.min(tooltip.pos.y + 6, 72)}%`,
          background:'#14151c', border:'1px solid #2f3248',
          borderRadius:8, padding:'8px 11px', minWidth:148,
          boxShadow:'0 12px 32px rgba(0,0,0,.55)',
        }}>
          <div style={{ fontWeight:700, fontSize:12, color:'#e2e4f0', marginBottom:3 }}>
            {tooltip.dev.name}
          </div>
          <div style={{ fontSize:11, color:'#8b8fa8', fontFamily:'monospace' }}>
            {tooltip.dev.ip}
          </div>
          <div style={{ fontSize:10, color:'#5a5d75', marginTop:2, marginBottom:6 }}>
            {tooltip.dev.role}
          </div>
          <span className={`status-${tooltip.dev.status}`}>
            {tooltip.dev.status?.toUpperCase()}
          </span>
          {tooltip.dev.current_action && tooltip.dev.current_action !== 'none' && (
            <div style={{ marginTop:4, fontSize:10, color:'#ef4444' }}>
              Acțiune: {String(tooltip.dev.current_action).toUpperCase()}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
