import React, { useState, useEffect } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from 'recharts';
import { fetchLiveMLAnalysis } from '../services/api';
import { Activity } from 'lucide-react';

export default function TrafficChart() {
  const defaultData = [
    { time: '10:00', normal: 1100, suspicious: 180, malicious: 20 },
    { time: '10:10', normal: 1150, suspicious: 220, malicious: 30 },
    { time: '10:20', normal: 1050, suspicious: 260, malicious: 45 },
    { time: '10:30', normal: 1200, suspicious: 310, malicious: 90 },
    { time: '10:40', normal: 1120, suspicious: 390, malicious: 280 },
    { time: '10:45', normal: 950, suspicious: 420, malicious: 1520 },
    { time: '10:50', normal: 1080, suspicious: 340, malicious: 410 },
    { time: '11:00', normal: 1140, suspicious: 210, malicious: 60 }
  ];

  const [data, setData] = useState(defaultData);
  const [isLive, setIsLive] = useState(false);
  const [totalMalicious, setTotalMalicious] = useState(0);

  useEffect(() => {
    let isMounted = true;

    const poll = async () => {
      try {
        const res = await fetchLiveMLAnalysis();
        if (!isMounted) return;

        if (res && res.traffic_series && res.traffic_series.length > 0) {
          setData(res.traffic_series);
          setIsLive(true);
          const currentMalicious = res.traffic_series.reduce((sum, item) => sum + (item.malicious || 0), 0);
          setTotalMalicious(currentMalicious);
        }
      } catch (err) {
        // keep existing data
      }
    };

    poll();
    const interval = setInterval(poll, 2500);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs flex flex-col h-full">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-3 border-b border-slate-100 gap-2">
        <div className="flex items-center gap-2.5">
          <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight">
            Network Traffic Telemetry
          </h3>
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
            {isLive ? 'REAL-TIME STREAM' : 'SIMULATED'}
          </span>
        </div>

        {/* Legend */}
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

      {/* Chart */}
      <div className="mt-4 h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
            <defs>
              <linearGradient id="colorNormal" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="colorMalicious" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="colorSuspicious" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
              </linearGradient>
            </defs>

            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />

            <XAxis
              dataKey="time"
              axisLine={{ stroke: '#f1f5f9' }}
              tickLine={false}
              tick={{ fill: '#64748b', fontSize: 11 }}
            />

            <YAxis
              axisLine={false}
              tickLine={false}
              tick={{ fill: '#64748b', fontSize: 11 }}
            />

            <Tooltip
              contentStyle={{
                backgroundColor: '#ffffff',
                borderColor: '#e2e8f0',
                borderRadius: '0.5rem',
                fontSize: '12px',
                boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
                color: '#0f172a'
              }}
            />

            <Area
              type="monotone"
              dataKey="normal"
              stroke="#3b82f6"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#colorNormal)"
              name="Normal Traffic"
            />

            <Area
              type="monotone"
              dataKey="suspicious"
              stroke="#f59e0b"
              strokeWidth={1.5}
              fillOpacity={1}
              fill="url(#colorSuspicious)"
              name="Suspicious Probes"
            />

            <Area
              type="monotone"
              dataKey="malicious"
              stroke="#ef4444"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#colorMalicious)"
              name="Malicious Ingress"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Real-time Telemetry footer */}
      <div className="mt-3 pt-2 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-400">
        <span className="flex items-center gap-1.5">
          <Activity className="w-3.5 h-3.5 text-blue-500" />
          Rolling 12-minute time window • 2-minute bucket aggregation
        </span>
        {totalMalicious > 0 && (
          <span className="font-semibold text-red-600 bg-red-50 px-2 py-0.5 rounded border border-red-200">
            {totalMalicious} Malicious Flows in Window
          </span>
        )}
      </div>
    </div>
  );
}
