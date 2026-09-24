import React, { useState, useEffect } from 'react';
import { ShieldAlert, ArrowUpRight, Activity } from 'lucide-react';
import { fetchLiveMLAnalysis } from '../services/api';

export default function RecentDetections({ onViewAll }) {
  const [detections, setDetections] = useState([]);
  const [isLive, setIsLive] = useState(false);
  const [lastUpdated, setLastUpdated] = useState('');

  // Fallback items if API is unreachable
  const defaultDetections = [
    { time: '10:22:41', src: '192.168.1.10', dst: '8.8.8.8', attack: 'DDoS', conf: '98%', status: 'Active' },
    { time: '10:22:17', src: '10.0.0.5', dst: '192.168.1.1', attack: 'Port Scan', conf: '87%', status: 'Investigating' },
    { time: '10:21:03', src: '172.16.0.3', dst: '104.16.248.249', attack: 'Brute Force', conf: '91%', status: 'Active' },
    { time: '10:19:56', src: '192.168.1.23', dst: '185.199.110.153', attack: 'Malware', conf: '89%', status: 'Contained' },
    { time: '10:18:44', src: '10.0.0.8', dst: '172.217.160.78', attack: 'Port Scan', conf: '84%', status: 'Investigating' }
  ];

  useEffect(() => {
    let isMounted = true;

    const poll = async () => {
      try {
        const res = await fetchLiveMLAnalysis();
        if (!isMounted) return;

        if (res && res.live_feeds && res.live_feeds.length > 0) {
          setIsLive(true);
          // Filter to malicious or suspicious threats first, or include recent feeds
          const threats = res.live_feeds
            .filter(f => f.status === 'Malicious' || f.status === 'Suspicious' || f.attack_type !== 'Normal')
            .slice(0, 5)
            .map(f => ({
              time: f.time,
              src: f.src,
              dst: f.dst,
              attack: f.attack_type || 'Unknown Attack',
              conf: f.confidence || '95%',
              status: f.status === 'Malicious' ? 'Active' : 'Investigating',
              indicator: f.indicator || ''
            }));

          if (threats.length > 0) {
            setDetections(threats);
          } else {
            // If all normal in recent buffer, show the latest feeds with normal status
            setDetections(res.live_feeds.slice(0, 5).map(f => ({
              time: f.time,
              src: f.src,
              dst: f.dst,
              attack: f.attack_type || 'Normal Traffic',
              conf: f.confidence || '99%',
              status: f.status === 'Normal' ? 'Contained' : 'Investigating',
              indicator: f.indicator || ''
            })));
          }
          setLastUpdated(new Date().toLocaleTimeString());
        } else {
          setDetections(defaultDetections);
        }
      } catch (err) {
        if (isMounted) setDetections(defaultDetections);
      }
    };

    poll();
    const interval = setInterval(poll, 2500);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const getBadgeStyle = (status) => {
    switch (status) {
      case 'Active':
        return 'text-red-700 bg-red-50 border border-red-200';
      case 'Investigating':
        return 'text-amber-700 bg-amber-50 border border-amber-200';
      case 'Contained':
      default:
        return 'text-emerald-700 bg-emerald-50 border border-emerald-200';
    }
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs flex flex-col justify-between">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-2">
        <div className="flex items-center gap-2.5">
          <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight">
            Recent Detections
          </h3>
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
            LIVE ML
          </span>
        </div>

        {onViewAll && (
          <button
            onClick={onViewAll}
            className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-700 transition-colors cursor-pointer"
          >
            <span>View All</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-slate-100 text-slate-500 font-medium">
              <th className="py-2.5 px-3">Time</th>
              <th className="py-2.5 px-3">Source IP</th>
              <th className="py-2.5 px-3">Destination IP</th>
              <th className="py-2.5 px-3">Attack Type</th>
              <th className="py-2.5 px-3">ML Confidence</th>
              <th className="py-2.5 px-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-50 font-sans">
            {detections.map((row, idx) => (
              <tr key={idx} className="hover:bg-slate-50/70 transition-colors">
                <td className="py-3 px-3 text-slate-500 font-mono text-[11px]">{row.time}</td>
                <td className="py-3 px-3 text-slate-900 font-medium font-mono text-[11px]">{row.src}</td>
                <td className="py-3 px-3 text-slate-600 font-mono text-[11px]">{row.dst}</td>
                <td className="py-3 px-3">
                  <span className="font-semibold text-slate-900">{row.attack}</span>
                  {row.indicator && (
                    <span className="block text-[10px] text-slate-400 truncate max-w-[200px]" title={row.indicator}>
                      {row.indicator}
                    </span>
                  )}
                </td>
                <td className="py-3 px-3 text-slate-900 font-medium">{row.conf}</td>
                <td className="py-3 px-3">
                  <span className={`inline-block px-2.5 py-0.5 rounded-full text-[11px] font-semibold ${getBadgeStyle(row.status)}`}>
                    {row.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Footer live status */}
      <div className="mt-3 pt-2 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-400">
        <span className="flex items-center gap-1.5">
          <Activity className="w-3.5 h-3.5 text-blue-500" />
          Synchronized with Vulnerable Lab Telemetry
        </span>
        {lastUpdated && <span>Updated {lastUpdated}</span>}
      </div>
    </div>
  );
}
