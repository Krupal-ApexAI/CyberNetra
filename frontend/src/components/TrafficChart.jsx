import React, { useState } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';
import { Activity, BarChart3 } from 'lucide-react';

export default function TrafficChart({ data = [], scenario }) {
  const [metricMode, setMetricMode] = useState('both'); // 'both', 'packets', 'volume'

  // Format data with safe fallbacks
  const chartData = (data && data.length > 0) ? data.map((item) => ({
    time: item.timestamp ? item.timestamp.split(':').slice(0, 2).join(':') : '00:00',
    fullTime: item.timestamp || 'N/A',
    packets: item.packet_count || 0,
    volume: Number(item.traffic_volume || 0).toFixed(2),
    volumeNum: Number(item.traffic_volume || 0),
    classification: item.classification || 'Normal',
    source: item.source_ip || 'N/A',
    destination: item.destination_ip || 'N/A'
  })) : [];

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      const item = payload[0].payload;
      return (
        <div className="glass-panel-glow p-3 rounded-xl border border-slate-700 bg-slate-950/90 text-xs shadow-2xl space-y-1.5 font-mono">
          <div className="flex items-center justify-between border-b border-slate-800 pb-1.5 gap-4">
            <span className="text-slate-400 font-semibold">{item.fullTime}</span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-bold ${
                item.classification === 'Attack'
                  ? 'bg-rose-950 text-rose-400 border border-rose-600/50'
                  : item.classification === 'Suspicious'
                  ? 'bg-amber-950 text-amber-400 border border-amber-600/50'
                  : 'bg-emerald-950 text-emerald-400 border border-emerald-600/50'
              }`}
            >
              {item.classification}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-slate-300">
            <div>
              <span className="text-slate-500">Packets: </span>
              <span className="text-cyan-400 font-bold">{item.packets.toLocaleString()}</span>
            </div>
            <div>
              <span className="text-slate-500">Volume: </span>
              <span className="text-indigo-400 font-bold">{item.volume} MB/s</span>
            </div>
            <div className="col-span-2 text-[11px] text-slate-400 truncate">
              Src: <span className="text-slate-300">{item.source}</span>
            </div>
            <div className="col-span-2 text-[11px] text-slate-400 truncate">
              Dst: <span className="text-slate-300">{item.destination}</span>
            </div>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="w-full glass-panel rounded-2xl p-5 border border-slate-800/80 flex flex-col justify-between">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-3 mb-2 border-b border-slate-800/60 gap-2">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold tracking-wide text-slate-200">
              Live Network Telemetry & Flow Ingress
            </h3>
            <p className="text-xs text-slate-400">
              Packet throughput (pkts) and volume (MB/s) telemetry timeline
            </p>
          </div>
        </div>

        {/* Filter controls */}
        <div className="flex items-center gap-1 bg-slate-900/80 border border-slate-800 p-1 rounded-lg text-xs">
          <button
            onClick={() => setMetricMode('both')}
            className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
              metricMode === 'both' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All Metrics
          </button>
          <button
            onClick={() => setMetricMode('packets')}
            className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
              metricMode === 'packets' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Packets
          </button>
          <button
            onClick={() => setMetricMode('volume')}
            className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
              metricMode === 'volume' ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Volume (MB/s)
          </button>
        </div>
      </div>

      {/* Recharts Area Container */}
      <div className="w-full h-72 sm:h-80 pt-2">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 10, right: 15, left: -10, bottom: 0 }}>
            <defs>
              <linearGradient id="cyanGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.45} />
                <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="indigoGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#818cf8" stopOpacity={0.40} />
                <stop offset="95%" stopColor="#818cf8" stopOpacity={0.0} />
              </linearGradient>
            </defs>

            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
            <XAxis
              dataKey="time"
              stroke="#64748b"
              tick={{ fontSize: 11, fill: '#94a3b8' }}
              tickLine={false}
              axisLine={{ stroke: '#334155' }}
            />
            <YAxis
              yAxisId="left"
              stroke="#06b6d4"
              tick={{ fontSize: 11, fill: '#06b6d4' }}
              tickLine={false}
              axisLine={false}
              tickFormatter={(v) => v >= 1000 ? `${(v / 1000).toFixed(0)}k` : v}
            />
            <YAxis
              yAxisId="right"
              orientation="right"
              stroke="#818cf8"
              tick={{ fontSize: 11, fill: '#818cf8' }}
              tickLine={false}
              axisLine={false}
              tickFormatter={(v) => `${v}M`}
            />

            <Tooltip content={<CustomTooltip />} />

            {(metricMode === 'both' || metricMode === 'packets') && (
              <Area
                yAxisId="left"
                type="monotone"
                dataKey="packets"
                name="Packet Count"
                stroke="#06b6d4"
                strokeWidth={2.5}
                fillOpacity={1}
                fill="url(#cyanGradient)"
              />
            )}

            {(metricMode === 'both' || metricMode === 'volume') && (
              <Area
                yAxisId="right"
                type="monotone"
                dataKey="volumeNum"
                name="Traffic Volume (MB/s)"
                stroke="#818cf8"
                strokeWidth={2.5}
                fillOpacity={1}
                fill="url(#indigoGradient)"
              />
            )}
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Legend & Stats Footer */}
      <div className="flex flex-wrap items-center justify-between pt-3 mt-1 border-t border-slate-800/60 text-xs text-slate-400">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
            <span className="font-mono text-slate-300">Packet Rate (ingress)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-indigo-400" />
            <span className="font-mono text-slate-300">Bandwidth Volume (MB/s)</span>
          </div>
        </div>
        <div className="text-[11px] font-mono text-slate-500">
          Sample Window: {chartData.length} records | NTRO Packet Capture Pipeline
        </div>
      </div>
    </div>
  );
}
