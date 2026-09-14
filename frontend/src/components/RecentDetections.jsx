import React from 'react';

export default function RecentDetections({ onViewAll }) {
  const detections = [
    { time: '10:22:41', src: '192.168.1.10', dst: '8.8.8.8', attack: 'DDoS', conf: '98%', status: 'Active' },
    { time: '10:22:17', src: '10.0.0.5', dst: '192.168.1.1', attack: 'Port Scan', conf: '87%', status: 'Investigating' },
    { time: '10:21:03', src: '172.16.0.3', dst: '104.16.248.249', attack: 'Brute Force', conf: '91%', status: 'Active' },
    { time: '10:19:56', src: '192.168.1.23', dst: '185.199.110.153', attack: 'Malware', conf: '89%', status: 'Contained' },
    { time: '10:18:44', src: '10.0.0.8', dst: '172.217.160.78', attack: 'Port Scan', conf: '84%', status: 'Investigating' }
  ];

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
    <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-2">
        <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight">
          Recent Detections
        </h3>
        {onViewAll && (
          <button
            onClick={onViewAll}
            className="text-xs font-semibold text-blue-600 hover:text-blue-700 transition-colors cursor-pointer"
          >
            View All
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
              <th className="py-2.5 px-3">Confidence</th>
              <th className="py-2.5 px-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-50 font-sans">
            {detections.map((row, idx) => (
              <tr key={idx} className="hover:bg-slate-50/70 transition-colors">
                <td className="py-3 px-3 text-slate-500">{row.time}</td>
                <td className="py-3 px-3 text-slate-900 font-medium">{row.src}</td>
                <td className="py-3 px-3 text-slate-700">{row.dst}</td>
                <td className="py-3 px-3 text-slate-900 font-semibold">{row.attack}</td>
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
    </div>
  );
}
