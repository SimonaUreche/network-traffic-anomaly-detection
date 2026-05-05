import { useState } from 'react';
import './index.css';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import Incidents from './pages/Incidents';
import Devices from './pages/Devices';
import { usePolling } from './hooks/usePolling';

export default function App() {
  const [page, setPage] = useState('dashboard');
  const [search, setSearch] = useState('');
  const { stats, incidents, devices, timeline, blocks, loading } = usePolling(3000);

  const props = { stats, incidents, devices, timeline, blocks, search };

  return (
    <div style={{ height:'100vh', display:'flex', flexDirection:'column', overflow:'hidden' }}>
      <Navbar page={page} setPage={setPage} search={search} setSearch={setSearch} />

      {loading ? (
        <div style={{
          flex:1, display:'flex', alignItems:'center', justifyContent:'center',
          flexDirection:'column', gap:12, color:'#5a5d75',
        }}>
          <div style={{
            width:32, height:32, borderRadius:'50%',
            border:'3px solid #22243a', borderTopColor:'#d4a520',
            animation:'spin 1s linear infinite',
          }} />
          <div style={{ fontSize:12 }}>Connecting to API…</div>
          <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
        </div>
      ) : (
        <main
          style={{
            flex: 1,
            minHeight: 0,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
          }}
        >
          {page === 'dashboard' && <Dashboard {...props} />}
          {page === 'incidents' && <Incidents {...props} />}
          {page === 'devices' && <Devices {...props} />}
        </main>
      )}
    </div>
  );
}
