import React from 'react';
import { ArrowUp, ArrowDown } from 'lucide-react';

export default function StatCards({ stats, scenario }) {
  const cards = [
    {
      title: 'Total Flows',
      value: '12,438',
      trend: '8.3%',
      isUp: true,
      trendColor: 'text-emerald-700 bg-emerald-50',
      sparkColor: '#3b82f6',
      // SVG path for mini sparkline
      sparkPath: 'M0,18 Q15,16 30,12 T60,6 T90,14 T120,4'
    },
    {
      title: 'Threats Detected',
      value: '173',
      trend: '12.6%',
      isUp: true,
      trendColor: 'text-red-700 bg-red-50',
      sparkColor: '#ef4444',
      sparkPath: 'M0,16 Q20,18 40,15 T80,8 T100,12 T120,3'
    },
    {
      title: 'Suspicious Flows',
      value: '89',
      trend: '4.2%',
      isUp: false,
      trendColor: 'text-amber-700 bg-amber-50',
      sparkColor: '#f59e0b',
      sparkPath: 'M0,6 Q20,4 40,8 T70,12 T100,10 T120,18'
    },
    {
      title: 'Normal Flows',
      value: '12,176',
      trend: '6.1%',
      isUp: true,
      trendColor: 'text-emerald-700 bg-emerald-50',
      sparkColor: '#3b82f6',
      sparkPath: 'M0,16 Q25,12 50,15 T80,10 T105,8 T120,4'
    }
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card, idx) => (
        <div
          key={idx}
          className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs flex items-center justify-between"
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
  );
}
