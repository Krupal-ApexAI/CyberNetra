import React from 'react';
import { Clock, ShieldAlert } from 'lucide-react';

export default function AttackTimeline() {
  const events = [
    { time: '10:20:15', title: 'Reconnaissance Scan', desc: 'Port sweep and TCP SYN probes detected from 10.0.0.5 targeting internal servers.', phase: 'Reconnaissance', status: 'Completed', color: 'text-amber-700 bg-amber-50 border-amber-200' },
    { time: '10:22:40', title: 'Initial SYN Flood Surge', desc: 'Sudden spike of 1,520 packets/sec originating from 192.168.1.10 targeting 8.8.8.8.', phase: 'Weaponization & Delivery', status: 'Active', color: 'text-red-700 bg-red-50 border-red-200' },
    { time: '10:23:41', title: 'Backlog Buffer Saturation', desc: 'Kernel TCP connection table reaches 92% capacity on target port 80/443.', phase: 'Execution', status: 'Active', color: 'text-red-700 bg-red-50 border-red-200' },
    { time: '10:24:17', title: 'Rate Limiting Playbook Triggered', desc: 'Automated BGP Flowspec and iptables rate limiting applied by CyberNetra AI.', phase: 'Mitigation', status: 'Contained', color: 'text-emerald-700 bg-emerald-50 border-emerald-200' }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-slate-900 font-sans tracking-tight">
          Attack Timeline
        </h2>
        <p className="text-xs text-slate-500 mt-1">
          Chronological kill-chain progression and automated mitigation milestones
        </p>
      </div>

      {/* Timeline Card */}
      <div className="bg-white rounded-xl border border-slate-200/90 p-8 shadow-xs">
        <div className="relative pl-6 space-y-8 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
          {events.map((evt, idx) => (
            <div key={idx} className="relative group">
              {/* Marker */}
              <div className="absolute -left-[27px] top-1.5 w-4 h-4 rounded-full border-2 border-white bg-blue-600 shadow-sm" />

              {/* Event Content */}
              <div className="bg-slate-50/70 hover:bg-slate-50 rounded-xl border border-slate-200/80 p-4 transition-all">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-semibold text-slate-900">
                      {evt.time}
                    </span>
                    <span className="text-xs text-slate-400 font-medium">
                      • {evt.phase}
                    </span>
                  </div>

                  <span className={`inline-block text-[11px] font-semibold px-2 py-0.5 rounded-full border self-start sm:self-auto ${evt.color}`}>
                    {evt.status}
                  </span>
                </div>

                <h3 className="text-sm font-bold text-slate-900 font-sans">
                  {evt.title}
                </h3>
                <p className="text-xs text-slate-600 mt-1 leading-relaxed">
                  {evt.desc}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
