import React, { useState, useEffect } from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';
import { fetchThreats, fetchLiveMLAnalysis } from '../services/api';

const COLOR_MAP = {
  'dos_attack': '#ef4444',
  'ddos': '#ef4444',
  'sqli_attack': '#dc2626',
  'sql injection': '#dc2626',
  'exploits': '#dc2626',
  'xss_attack': '#f97316',
  'cross-site scripting': '#f97316',
  'cmdi_attack': '#b91c1c',
  'command injection': '#b91c1c',
  'brute_force_attack': '#f59e0b',
  'bruteforce': '#f59e0b',
  'traversal_attack': '#eab308',
  'reconnaissance': '#3b82f6',
  'port scan': '#3b82f6',
  'malware': '#8b5cf6',
  'generic': '#64748b',
  'others': '#94a3b8',
};

export default function ThreatDistribution() {
  const defaultData = [
    { name: 'DDoS', value: 38, color: '#ef4444' },
    { name: 'Port Scan', value: 21, color: '#3b82f6' },
    { name: 'Brute Force', value: 18, color: '#f59e0b' },
    { name: 'Malware', value: 12, color: '#8b5cf6' },
    { name: 'Others', value: 11, color: '#94a3b8' }
  ];

  const [data, setData] = useState(defaultData);
  const [totalThreats, setTotalThreats] = useState(173);
  const [isLive, setIsLive] = useState(false);

  useEffect(() => {
    let isMounted = true;

    const poll = async () => {
      try {
        const [threatsRes, mlRes] = await Promise.all([
          fetchThreats(),
          fetchLiveMLAnalysis()
        ]);

        if (!isMounted) return;

        // If we have live threats from the lab
        if (threatsRes && threatsRes.data && threatsRes.data.length > 0) {
          setIsLive(true);
          const totalEvents = threatsRes.data.reduce((sum, t) => sum + (t.event_count || 1), 0);
          setTotalThreats(totalEvents);

          const items = threatsRes.data.map(t => {
            const key = (t.type || t.name || '').toLowerCase();
            const color = COLOR_MAP[key] || '#f59e0b';
            return {
              name: t.name,
              value: t.event_count || 1,
              color: color
            };
          });

          // Add others if small
          setData(items);
        } else if (mlRes && mlRes.live_feeds && mlRes.live_feeds.length > 0) {
          // Fall back to live feed classification distribution
          const counts = {};
          let maliciousCount = 0;
          mlRes.live_feeds.forEach(f => {
            if (f.status === 'Malicious' || f.status === 'Suspicious') {
              const attack = f.attack_type || 'Generic';
              counts[attack] = (counts[attack] || 0) + 1;
              maliciousCount++;
            }
          });

          if (maliciousCount > 0) {
            setIsLive(true);
            setTotalThreats(maliciousCount);
            const items = Object.entries(counts).map(([name, val]) => ({
              name,
              value: val,
              color: COLOR_MAP[name.toLowerCase()] || '#3b82f6'
            }));
            setData(items);
          }
        }
      } catch (err) {
        // preserve fallback
      }
    };

    poll();
    const interval = setInterval(poll, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs flex flex-col h-full justify-between">
      {/* Title */}
      <div className="pb-3 border-b border-slate-100 mb-2 flex items-center justify-between">
        <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight">
          Threat Distribution
        </h3>
        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
          {isLive ? 'LIVE LAB' : 'BASELINE'}
        </span>
      </div>

      {/* Donut & Legend Container */}
      <div className="flex-1 flex flex-col sm:flex-row items-center justify-between gap-4 my-2">
        {/* Donut Chart */}
        <div className="relative w-40 h-40 shrink-0 flex items-center justify-center">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Tooltip
                contentStyle={{
                  backgroundColor: '#ffffff',
                  borderColor: '#e2e8f0',
                  borderRadius: '0.375rem',
                  fontSize: '12px',
                  color: '#0f172a'
                }}
              />
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={48}
                outerRadius={68}
                paddingAngle={2}
                dataKey="value"
                stroke="none"
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>

          {/* Center Text */}
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center">
            <span className="text-2xl font-extrabold text-slate-900 font-sans leading-none">
              {totalThreats}
            </span>
            <span className="text-[11px] font-medium text-slate-500 mt-1">
              Events
            </span>
          </div>
        </div>

        {/* Legend */}
        <div className="flex flex-col gap-2 w-full sm:w-auto font-sans">
          {data.map((item, idx) => (
            <div key={idx} className="flex items-center justify-between sm:justify-start gap-3 text-xs">
              <div className="flex items-center gap-2">
                <span
                  className="w-2.5 h-2.5 rounded-full shrink-0"
                  style={{ backgroundColor: item.color }}
                />
                <span className="text-slate-700 font-medium text-xs">{item.name}</span>
              </div>
              <span className="text-slate-900 font-bold ml-auto font-mono text-[11px]">
                {item.value}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="pt-2 border-t border-slate-100 text-[11px] text-slate-400">
        Attack vector clustering via UNSW-NB15 classifier
      </div>
    </div>
  );
}
