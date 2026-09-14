import React from 'react';

export default function SystemHealth() {
  const services = [
    { name: 'Model Service', status: 'Operational' },
    { name: 'Log Ingestion', status: 'Operational' },
    { name: 'Database', status: 'Operational' },
    { name: 'AI Explanation Service', status: 'Operational' }
  ];

  return (
    <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs flex flex-col h-full">
      {/* Title */}
      <div className="pb-3 border-b border-slate-100 mb-2">
        <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight">
          System Health
        </h3>
      </div>

      {/* Services List */}
      <div className="space-y-3.5 flex-1 flex flex-col justify-center">
        {services.map((svc, idx) => (
          <div
            key={idx}
            className="flex items-center justify-between text-xs py-1"
          >
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-xs" />
              <span className="text-slate-700 font-medium">{svc.name}</span>
            </div>
            <span className="text-emerald-700 font-medium text-[11px] bg-emerald-50 px-2 py-0.5 rounded">
              {svc.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
