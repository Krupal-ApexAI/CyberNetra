import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';

export default function ThreatDistribution() {
  const data = [
    { name: 'DDoS', value: 38, color: '#ef4444' },
    { name: 'Port Scan', value: 21, color: '#3b82f6' },
    { name: 'Brute Force', value: 18, color: '#f59e0b' },
    { name: 'Malware', value: 12, color: '#8b5cf6' },
    { name: 'Others', value: 11, color: '#94a3b8' }
  ];

  return (
    <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs flex flex-col h-full">
      {/* Title */}
      <div className="pb-3 border-b border-slate-100 mb-2">
        <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight">
          Threat Distribution
        </h3>
      </div>

      {/* Donut & Legend Container */}
      <div className="flex-1 flex flex-col sm:flex-row items-center justify-between gap-4">
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
              173
            </span>
            <span className="text-[11px] font-medium text-slate-500 mt-1">
              Threats
            </span>
          </div>
        </div>

        {/* Legend */}
        <div className="flex-1 w-full space-y-2.5 pl-2">
          {data.map((item, idx) => (
            <div key={idx} className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span
                  className="w-2.5 h-2.5 rounded-full shrink-0"
                  style={{ backgroundColor: item.color }}
                />
                <span className="text-slate-700 font-medium">{item.name}</span>
              </div>
              <span className="text-slate-900 font-bold">{item.value}%</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
