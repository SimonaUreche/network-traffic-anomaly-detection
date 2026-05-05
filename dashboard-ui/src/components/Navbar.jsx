import { Shield, Search, LayoutDashboard, AlertTriangle, Cpu } from 'lucide-react';

const TABS = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'incidents', label: 'Incidents', icon: AlertTriangle },
  { id: 'devices',   label: 'Devices',   icon: Cpu },
];

export default function Navbar({ page, setPage, search, setSearch }) {
  return (
    <nav style={{
      display: 'flex', alignItems: 'center', gap: 16,
      height: 52, padding: '0 20px',
      background: 'rgba(13,14,21,.92)',
      borderBottom: '1px solid rgba(30,32,48,.9)',
      position: 'sticky', top: 0, zIndex: 100,
      backdropFilter: 'blur(10px)',
    }}>
      {/* Logo */}
      <div style={{ display:'flex', alignItems:'center', gap:8, minWidth:0, flexShrink:0, marginRight:8 }}>
        <div style={{
          width:32, height:32, borderRadius:8,
          background:'linear-gradient(135deg,#d4a520,#a07810)',
          display:'flex', alignItems:'center', justifyContent:'center',
        }}>
          <Shield size={17} color="#000" strokeWidth={2.5} />
        </div>
        <div>
          <div style={{ fontSize:13, fontWeight:700, color:'#e2e4f0', lineHeight:1.1 }}>IoT IDPS</div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display:'flex', gap:4 }}>
        {TABS.map(({ id, label, icon: Icon }) => {
          const active = page === id;
          return (
            <button key={id} onClick={() => setPage(id)} style={{
              display:'flex', alignItems:'center', gap:6,
              padding:'6px 14px',
              borderRadius:8,
              fontSize:12,
              fontWeight:700,
              background: active ? '#d4a520' : 'transparent',
              color: active ? '#0a0b0f' : '#8b8fa8',
              border: active ? '1px solid rgba(212,165,32,.65)' : '1px solid transparent',
              transition:'all .15s',
            }}>
              <Icon size={13} />
              {label}
            </button>
          );
        })}
      </div>

      {/* Search */}
      <div style={{ flex:1, maxWidth:300, position:'relative', marginLeft:'auto' }}>
        <Search size={13} style={{ position:'absolute', left:10, top:'50%', transform:'translateY(-50%)', color:'#5a5d75' }} />
        <input
          value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search incidents, IPs, devices..."
          style={{
            width:'100%', padding:'6px 10px 6px 30px',
            background:'rgba(19,20,27,.9)', border:'1px solid rgba(34,36,58,.95)',
            borderRadius:8, color:'#e2e4f0', fontSize:12,
            outline:'none',
          }}
        />
      </div>

      {/* Status */}
      <div style={{
        display:'flex', alignItems:'center', gap:8, flexShrink:0,
        padding:'6px 10px', borderRadius:999,
        background:'rgba(34,197,94,.10)', border:'1px solid rgba(34,197,94,.20)',
      }}>
        <span style={{
          width:7, height:7, borderRadius:'50%', background:'#22c55e',
          boxShadow:'0 0 6px #22c55e',
          animation: 'pulse 2s infinite',
        }} />
        <span style={{ fontSize:12, color:'#22c55e', fontWeight:600 }}>Monitoring Active</span>
      </div>

      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}`}</style>
    </nav>
  );
}
