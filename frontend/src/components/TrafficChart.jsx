import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from 'recharts';

export default function TrafficChart() {
  const data = [
    { time: '10:00', normal: 1100, suspicious: 180, malicious: 20 },
    { time: '10:10', normal: 1150, suspicious: 220, malicious: 30 },
    { time: '10:20', normal: 1050, suspicious: 260, malicious: 45 },
    { time: '10:30', normal: 1200, suspicious: 310, malicious: 90 },
    { time: '10:40', normal: 1120, suspicious: 390, malicious: 280 },
    { time: '10:45', normal: 950, suspicious: 420, malicious: 1520 },
    { time: '10:50', normal: 1080, suspicious: 340, malicious: 410 },
    { time: '11:00', normal: 1140, suspicious: 210, malicious: 60 }
  ];

  return (
    <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs flex flex-col h-full">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-3 border-b border-slate-100 gap-2">
        <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight">
          Network Traffic
        </h3>

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
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
            <XAxis
              dataKey="time"
              stroke="#94a3b8"
              tick={{ fontSize: 11, fill: '#64748b' }}
              tickLine={false}
              axisLine={{ stroke: '#e2e8f0' }}
            />
            <YAxis
              stroke="#94a3b8"
              tick={{ fontSize: 11, fill: '#64748b' }}
              tickLine={false}
              axisLine={false}
              domain={[0, 2000]}
              ticks={[0, 500, 1000, 1500, 2000]}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#ffffff',
                borderColor: '#e2e8f0',
                borderRadius: '0.5rem',
                fontSize: '12px',
                color: '#0f172a',
                boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)'
              }}
            />
            <Area
              type="monotone"
              dataKey="normal"
              name="Normal Traffic"
              stroke="#3b82f6"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#colorNormal)"
            />
            <Area
              type="monotone"
              dataKey="suspicious"
              name="Suspicious Traffic"
              stroke="#f59e0b"
              strokeWidth={1.5}
              fill="none"
            />
            <Area
              type="monotone"
              dataKey="malicious"
              name="Malicious Traffic"
              stroke="#ef4444"
              strokeWidth={2.5}
              fillOpacity={1}
              fill="url(#colorMalicious)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
