import { useState, useEffect, useCallback } from 'react';

const BASE = 'http://localhost:5001/api';

export function usePolling(interval = 3000) {
  const [data, setData] = useState({
    stats: null, incidents: [], devices: [], timeline: [], blocks: { blocks: [], isolations: [] },
  });
  const [loading, setLoading] = useState(true);

  const fetchAll = useCallback(async () => {
    try {
      const [stats, incidents, devices, timeline, blocks] = await Promise.all([
        fetch(`${BASE}/stats`).then(r => r.json()),
        fetch(`${BASE}/incidents`).then(r => r.json()),
        fetch(`${BASE}/devices`).then(r => r.json()),
        fetch(`${BASE}/timeline`).then(r => r.json()),
        fetch(`${BASE}/blocks`).then(r => r.json()),
      ]);
      setData({ stats, incidents: incidents.incidents || [], devices: devices.devices || [], timeline: timeline.timeline || [], blocks });
      setLoading(false);
    } catch (e) {
      console.error('API error:', e);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const id = setInterval(fetchAll, interval);
    return () => clearInterval(id);
  }, [fetchAll, interval]);

  return { ...data, loading, refresh: fetchAll };
}
