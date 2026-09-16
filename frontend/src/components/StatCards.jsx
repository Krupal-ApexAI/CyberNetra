import React from 'react';
import { ArrowUp, ArrowDown } from 'lucide-react';

export default function StatCards({ stats, scenario }) {
  const totalFlows = stats?.total_flows != null ? Number(stats.total_flows).toLocaleString() : '12,438';
  const threatsDetected = stats?.threats_detected != null ? Number(stats.threats_detected).toLocaleString() : '173';
  const suspiciousFlows = stats?.suspicious_flows != null ? Number(stats.suspicious_flows).toLocaleString() : '89';
  const normalFlows = stats?.normal_flows != null ? Number(stats.normal_flows).toLocaleString() : '12,176';

  const trends = stats?.trends || {};

  const cards = [
    {
      title: 'Total Flows',
      value: totalFlows,
      trend: trends.total?.value || '8.3%',
      isUp: trends.total?.is_up ?? true,
      trendColor: (trends.total?.is_up ?? true) ? 'text-emerald-700 bg-emerald-50' : 'text-slate-600 bg-slate-50',
      sparkColor: trends.total?.sparkColor || '#3b82f6',
      sparkPath: trends.total?.sparkPath || 'M0,18 Q15,16 30,12 T60,6 T90,14 T120,4'
    },
    {
      title: 'Threats Detected',
      value: threatsDetected,
      trend: trends.threats?.value || '12.6%',
      isUp: trends.threats?.is_up ?? true,
      trendColor: 'text-red-700 bg-red-50',
      sparkColor: trends.threats?.sparkColor || '#ef4444',
      sparkPath: trends.threats?.sparkPath || 'M0,16 Q20,18 40,15 T80,8 T100,12 T120,3'
    },
    {
      title: 'Suspicious Flows',
      value: suspiciousFlows,
      trend: trends.suspicious?.value || '4.2%',
      isUp: trends.suspicious?.is_up ?? false,
      trendColor: (trends.suspicious?.is_up ?? false) ? 'text-red-700 bg-red-50' : 'text-amber-700 bg-amber-50',
      sparkColor: trends.suspicious?.sparkColor || '#f59e0b',
      sparkPath: trends.suspicious?.sparkPath || 'M0,6 Q20,4 40,8 T70,12 T100,10 T120,18'
    },
    {
      title: 'Normal Flows',
      value: normalFlows,
      trend: trends.normal?.value || '6.1%',
      isUp: trends.normal?.is_up ?? true,
      trendColor: 'text-emerald-700 bg-emerald-50',
      sparkColor: trends.normal?.sparkColor || '#10b981',
      sparkPath: trends.normal?.sparkPath || 'M0,16 Q25,12 50,15 T80,10 T105,8 T120,4'
    }
  ];

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between px-1">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Live Network Telemetry Stream
          </span>
        </div>
        {stats?.flow_rate_per_sec && (
          <span className="text-[11px] text-slate-400 font-mono">
            {stats.flow_rate_per_sec} pkts/s • {stats.bandwidth_mbps} Mbps
          </span>
        )}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((card, idx) => (
          <div
            key={idx}
            className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs flex items-center justify-between hover:border-slate-300 transition-all"
          >
            <div>
              <p className="text-xs font-medium text-slate-500 font-sans">
                {card.title}
              </p>
              <h3 className="text-2xl sm:text-3xl font-bold text-slate-900 font-sans tracking-tight mt-1.5">
                {card.value}
              </h3>
              <div className="mt-2 flex items-center gap-1.5">
                <span
                  className={`inline-flex items-center gap-0.5 text-xs font-semibold px-1.5 py-0.5 rounded ${card.trendColor}`}
                >
                  {card.isUp ? (
                    <ArrowUp className="w-3 h-3 stroke-[2.5]" />
                  ) : (
                    <ArrowDown className="w-3 h-3 stroke-[2.5]" />
                  )}
                  <span>{card.trend}</span>
                </span>
                <span className="text-[10px] text-slate-400">vs baseline</span>
              </div>
            </div>

            {/* Mini Sparkline Chart */}
            <div className="w-24 h-12 flex items-center justify-end">
              <svg viewBox="0 0 120 24" className="w-full h-8 overflow-visible">
                <path
                  d={card.sparkPath}
                  fill="none"
                  stroke={card.sparkColor}
                  strokeWidth="2.5"
                  strokeLinecap="round"
                />
              </svg>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
