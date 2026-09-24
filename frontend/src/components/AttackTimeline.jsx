import React, { useState, useEffect } from 'react';
import { Clock, ShieldAlert, Activity, CheckCircle2, AlertTriangle, ExternalLink } from 'lucide-react';
import { fetchTimeline } from '../services/api';

export default function AttackTimeline({ onSelectTab }) {
  const [events, setEvents] = useState([]);
  const [isLive, setIsLive] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState('');

  const defaultEvents = [
    { time: '10:20:15', title: 'Reconnaissance Scan', desc: 'Port sweep and TCP SYN probes detected from 10.0.0.5 targeting internal servers.', phase: 'Reconnaissance', status: 'Completed', color: 'text-amber-700 bg-amber-50 border-amber-200', mitre_id: 'T1046' },
    { time: '10:22:40', title: 'Initial SYN Flood Surge', desc: 'Sudden spike of 1,520 packets/sec originating from 192.168.1.10 targeting 8.8.8.8.', phase: 'Weaponization & Delivery', status: 'Active', color: 'text-red-700 bg-red-50 border-red-200', mitre_id: 'T1498' },
    { time: '10:23:41', title: 'Backlog Buffer Saturation', desc: 'Kernel TCP connection table reaches 92% capacity on target port 80/443.', phase: 'Execution', status: 'Active', color: 'text-red-700 bg-red-50 border-red-200', mitre_id: 'T1498' },
    { time: '10:24:17', title: 'Rate Limiting Playbook Triggered', desc: 'Automated BGP Flowspec and iptables rate limiting applied by CyberNetra AI.', phase: 'Mitigation', status: 'Contained', color: 'text-emerald-700 bg-emerald-50 border-emerald-200', mitre_id: '' }
  ];

  useEffect(() => {
    let isMounted = true;

    const poll = async () => {
      try {
        const res = await fetchTimeline();
        if (!isMounted) return;

        if (res && res.data && res.data.length > 0) {
          setEvents(res.data);
          setIsLive(res.source === 'live_lab');
          setLastRefreshed(new Date().toLocaleTimeString());
        } else {
          setEvents(defaultEvents);
        }
      } catch (err) {
        if (isMounted) setEvents(defaultEvents);
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
    <div className="space-y-6 font-sans">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="text-2xl font-bold text-slate-900 font-sans tracking-tight">
              Attack Timeline & Kill Chain
            </h2>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              {isLive ? 'LIVE KILL-CHAIN STREAM' : 'BASELINE PROFILE'}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Chronological kill-chain progression and automated mitigation milestones driven by Vulnerable Lab telemetry
          </p>
        </div>

        {lastRefreshed && (
          <span className="text-xs text-slate-400 font-mono">
            Synced: {lastRefreshed}
          </span>
        )}
      </div>

      {/* Lab Banner if not live */}
      {!isLive && (
        <div className="bg-blue-50 border border-blue-200/80 rounded-xl p-3.5 flex items-center justify-between text-xs text-blue-900">
          <div className="flex items-center gap-2.5">
            <Activity className="w-4 h-4 text-blue-600 shrink-0" />
            <span>
              <strong>Ready for Live Attack Progression.</strong> Trigger SQLi, XSS, DoS, Command Injection, or Brute Force in the <strong>Controlled Vulnerable Lab</strong> (:9000) to populate this kill-chain dynamically!
            </span>
          </div>
          {onSelectTab && (
            <button
              onClick={() => onSelectTab('lab')}
              className="inline-flex items-center gap-1 px-2.5 py-1 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition cursor-pointer shrink-0 ml-4"
            >
              <span>Launch Lab Attacks</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          )}
        </div>
      )}

      {/* Timeline Card */}
      <div className="bg-white rounded-xl border border-slate-200/90 p-6 sm:p-8 shadow-xs">
        <div className="relative pl-6 space-y-8 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
          {events.map((evt, idx) => (
            <div key={idx} className="relative group">
              {/* Marker */}
              <div
                className={`absolute -left-[27px] top-1.5 w-4 h-4 rounded-full border-2 border-white shadow-sm ${
                  evt.phase === 'Exploitation' || evt.phase === 'Execution' || evt.phase === 'Impact'
                    ? 'bg-red-600 animate-pulse'
                    : evt.phase === 'Discovery' || evt.phase === 'Credential Access'
                    ? 'bg-amber-500'
                    : 'bg-blue-600'
                }`}
              />

              {/* Event Content */}
              <div className="bg-slate-50/70 hover:bg-slate-50 rounded-xl border border-slate-200/80 p-4 transition-all">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-semibold text-slate-900">
                      {evt.time}
                    </span>
                    <span className="text-xs text-slate-500 font-medium">
                      • {evt.phase}
                    </span>
                    {evt.mitre_id && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold text-slate-600 bg-slate-200/60">
                        {evt.mitre_id}
                      </span>
                    )}
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

                {evt.source_ip && (
                  <div className="mt-2 pt-2 border-t border-slate-200/60 flex items-center gap-2 text-[11px] text-slate-500 font-mono">
                    <span>Source: {evt.source_ip}</span>
                    <span>→</span>
                    <span>Target: Controlled Lab (Port 9000)</span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
