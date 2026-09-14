import React, { useState } from 'react';
import { Pause, Play, ChevronDown, SlidersHorizontal } from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from 'recharts';

export default function LiveMonitoring() {
  const [isPaused, setIsPaused] = useState(false);

  const trafficData = [
    { time: '10:45', normal: 1100, suspicious: 180, malicious: 50 },
    { time: '10:46', normal: 1150, suspicious: 240, malicious: 90 },
    { time: '10:47', normal: 1080, suspicious: 290, malicious: 180 },
    { time: '10:48', normal: 950, suspicious: 340, malicious: 1150 },
    { time: '10:49', normal: 1120, suspicious: 280, malicious: 320 },
    { time: '10:50', normal: 1160, suspicious: 210, malicious: 60 }
  ];

  const liveFeeds = [
    { time: '10:50:12', src: '192.168.1.10', dst: '8.8.8.8', proto: 'TCP', size: '524', status: 'Malicious' },
    { time: '10:50:11', src: '10.0.0.5', dst: '192.168.1.1', proto: 'UDP', size: '230', status: 'Suspicious' },
    { time: '10:50:10', src: '172.16.0.3', dst: '104.16.248.249', proto: 'TCP', size: '312', status: 'Normal' },
    { time: '10:50:10', src: '192.168.1.23', dst: '185.199.110.153', proto: 'TCP', size: '620', status: 'Malicious' },
    { time: '10:50:10', src: '10.0.0.8', dst: '172.217.160.78', proto: 'UDP', size: '198', status: 'Normal' },
    { time: '10:50:09', src: '192.168.1.11', dst: '8.8.4.4', proto: 'TCP', size: '430', status: 'Suspicious' },
    { time: '10:50:08', src: '172.16.0.7', dst: '192.168.1.5', proto: 'TCP', size: '512', status: 'Normal' },
    { time: '10:50:08', src: '10.0.0.12', dst: '142.250.190.14', proto: 'UDP', size: '220', status: 'Normal' }
  ];

  const getStatusBadge = (status) => {
    switch (status) {
      case 'Malicious':
        return 'text-red-700 bg-red-50 border border-red-200';
      case 'Suspicious':
        return 'text-amber-700 bg-amber-50 border border-amber-200';
      case 'Normal':
      default:
        return 'text-emerald-700 bg-emerald-50 border border-emerald-200';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Matching Mockup 3 */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-900 font-sans tracking-tight">
            Live Monitoring
          </h2>
          <p className="text-xs text-slate-500 mt-1">
            Real-time network traffic and threat detection
          </p>
        </div>

        {/* Action Controls Matching Mockup 3 */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setIsPaused(!isPaused)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-xs font-semibold text-slate-700 hover:bg-slate-50 shadow-xs cursor-pointer"
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? 'Resume' : 'Pause'}</span>
          </button>

          <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-xs font-medium text-slate-700 hover:bg-slate-50 shadow-xs cursor-pointer">
            <span>Last 5 Minutes</span>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          </button>

          <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-xs font-medium text-slate-700 hover:bg-slate-50 shadow-xs cursor-pointer">
            <SlidersHorizontal className="w-3 h-3 text-slate-400" />
            <span>Filters</span>
          </button>
        </div>
      </div>

      {/* Live Network Traffic Chart Card Matching Mockup 3 */}
      <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-3 border-b border-slate-100 gap-2 mb-4">
          <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight">
            Live Network Traffic
          </h3>

          <div className="flex items-center gap-4 text-xs font-medium">
            <div className="flex items-center gap-1.5 text-blue-600">
              <span className="w-3 h-0.5 bg-blue-600 rounded-full" />
              <span className="text-slate-600">Normal</span>
            </div>
            <div className="flex items-center gap-1.5 text-amber-500">
              <span className="w-3 h-0.5 bg-amber-500 rounded-full" />
              <span className="text-slate-600">Suspicious</span>
            </div>
            <div className="flex items-center gap-1.5 text-red-500">
              <span className="w-3 h-0.5 bg-red-500 rounded-full" />
              <span className="text-slate-600">Malicious</span>
            </div>
          </div>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={trafficData} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
              <defs>
                <linearGradient id="liveNormal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="liveMalicious" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
              <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} />
              <YAxis stroke="#94a3b8" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} axisLine={false} domain={[0, 2000]} ticks={[0, 500, 1000, 1500, 2000]} />
              <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '0.375rem', fontSize: '12px' }} />
              <Area type="monotone" dataKey="normal" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#liveNormal)" />
              <Area type="monotone" dataKey="suspicious" stroke="#f59e0b" strokeWidth={1.5} fill="none" />
              <Area type="monotone" dataKey="malicious" stroke="#ef4444" strokeWidth={2.5} fillOpacity={1} fill="url(#liveMalicious)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Live Traffic Feed Table Card Matching Mockup 3 */}
      <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs">
        <div className="pb-3 border-b border-slate-100 mb-2">
          <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight">
            Live Traffic Feed
          </h3>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-100 text-slate-500 font-medium">
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">Destination IP</th>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Size</th>
                <th className="py-2.5 px-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50 font-sans">
              {liveFeeds.map((row, idx) => (
                <tr key={idx} className="hover:bg-slate-50/70 transition-colors">
                  <td className="py-2.5 px-3 text-slate-500">{row.time}</td>
                  <td className="py-2.5 px-3 text-slate-900 font-medium">{row.src}</td>
                  <td className="py-2.5 px-3 text-slate-700">{row.dst}</td>
                  <td className="py-2.5 px-3 text-slate-800 font-medium">{row.proto}</td>
                  <td className="py-2.5 px-3 text-slate-500">{row.size}</td>
                  <td className="py-2.5 px-3">
                    <span className={`inline-block px-2.5 py-0.5 rounded-full text-[11px] font-semibold ${getStatusBadge(row.status)}`}>
                      {row.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
