import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Download,
  CheckCircle2,
  AlertTriangle,
  ChevronRight,
  ExternalLink,
  Flame,
  Activity
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from 'recharts';
import { fetchThreats } from '../services/api';

export default function ThreatsPage({ onSelectTab }) {
  const [activeSubTab, setActiveSubTab] = useState('Overview');
  const [actionTaken, setActionTaken] = useState(false);
  const [threatsList, setThreatsList] = useState([]);
  const [selectedThreatIndex, setSelectedThreatIndex] = useState(0);
  const [isLive, setIsLive] = useState(false);

  // Baseline fallback threat
  const baselineThreat = {
    id: 'THR-BASE-DDOS-001',
    name: 'DDoS SYN Flood Attack',
    type: 'dos_attack',
    severity: 'Critical',
    confidence: '98%',
    source_ip: '192.168.1.10',
    dest_ip: '8.8.8.8:80',
    first_seen: '10:23:41',
    last_seen: '10:24:17',
    duration: '36 seconds',
    event_count: 12430,
    indicator: 'SYN Flood Ingress Spike on Gateway',
    mitre_id: 'T1498',
    mitre_name: 'Network Denial of Service',
    mitre_tactic: 'Impact (TA0040)',
    why_detected: [
      'Unusually high number of SYN packets exceeding 21,000 pkts/s',
      'Traffic rate significantly above baseline (+840% deviation)',
      'Repeated connection requests from distributed botnet workers',
      'Pattern matches known DDoS behavior (trained on UNSW-NB15 & CTU-13)'
    ],
    recommended_actions: [
      'Rate limit incoming SYN packets at the edge router',
      'Enable SYN cookies on web server ingress',
      'Deploy Cloudflare/CDN DDoS scrubbing layer',
      'Temporarily block suspicious source subnet ranges'
    ],
    traffic_pattern: [
      { time: '10:20', normal: 120, attack: 10 },
      { time: '10:21', normal: 135, attack: 20 },
      { time: '10:22', normal: 125, attack: 50 },
      { time: '10:23', normal: 110, attack: 680 },
      { time: '10:24', normal: 95, attack: 1840 },
      { time: '10:25', normal: 130, attack: 720 },
      { time: '10:26', normal: 140, attack: 150 }
    ]
  };

  useEffect(() => {
    let isMounted = true;

    const poll = async () => {
      try {
        const res = await fetchThreats();
        if (!isMounted) return;

        if (res && res.data && res.data.length > 0) {
          setThreatsList(res.data);
          setIsLive(true);
        } else {
          setThreatsList([baselineThreat]);
          setIsLive(false);
        }
      } catch (err) {
        if (isMounted) setThreatsList([baselineThreat]);
      }
    };

    poll();
    const interval = setInterval(poll, 2500);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const currentThreat = threatsList[selectedThreatIndex] || threatsList[0] || baselineThreat;

  const subTabs = [
    'Overview',
    'Attack Timeline',
    'Network Graph',
    'AI Explanation',
    'MITRE ATT&CK',
    'Raw Logs'
  ];

  const handleExport = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentThreat, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `forensic-report-${currentThreat.id || 'threat'}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Top Breadcrumb & Live Threat Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs text-slate-500 font-medium">
          <span className="cursor-pointer hover:text-slate-800">Threats</span>
          <span>/</span>
          <span className="text-slate-900 font-semibold">{currentThreat.name}</span>
          {isLive && (
            <span className="ml-2 inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-50 text-red-700 border border-red-200 animate-pulse">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
              LIVE LAB TELEMETRY
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {threatsList.length > 1 && (
            <div className="flex items-center gap-1 bg-white border border-slate-200 rounded-lg p-1 text-xs">
              <span className="text-slate-400 px-2 font-medium">Threat:</span>
              <select
                value={selectedThreatIndex}
                onChange={(e) => setSelectedThreatIndex(Number(e.target.value))}
                className="bg-transparent text-slate-800 font-semibold outline-none cursor-pointer pr-2"
              >
                {threatsList.map((t, idx) => (
                  <option key={idx} value={idx}>
                    {t.name} ({t.severity})
                  </option>
                ))}
              </select>
            </div>
          )}

          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-slate-50 text-xs font-semibold text-slate-700 shadow-xs cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Report</span>
          </button>
        </div>
      </div>

      {/* Lab Inactive Notification Banner */}
      {!isLive && (
        <div className="bg-blue-50 border border-blue-200/80 rounded-xl p-3.5 flex items-center justify-between text-xs text-blue-900">
          <div className="flex items-center gap-2.5">
            <Activity className="w-4 h-4 text-blue-600 shrink-0" />
            <span>
              <strong>Passive Baseline Profile Active.</strong> Fire attacks in the <strong>Controlled Vulnerable Lab</strong> (:9000) to inspect real-time SQLi, XSS, DoS, and Brute Force threat profiles dynamically!
            </span>
          </div>
          {onSelectTab && (
            <button
              onClick={() => onSelectTab('lab')}
              className="inline-flex items-center gap-1 px-2.5 py-1 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition cursor-pointer shrink-0 ml-4"
            >
              <span>Open Lab</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          )}
        </div>
      )}

      {/* Threat Summary Banner Card */}
      <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-red-50 border border-red-100 flex items-center justify-center shrink-0">
            <ShieldAlert className="w-6 h-6 text-red-500" />
          </div>

          <div>
            <div className="flex items-center gap-2.5">
              <h2 className="text-lg font-bold text-slate-900 font-sans">
                {currentThreat.name}
              </h2>
              <span
                className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ${
                  currentThreat.severity === 'Critical'
                    ? 'text-red-700 bg-red-50 border border-red-200'
                    : 'text-amber-700 bg-amber-50 border border-amber-200'
                }`}
              >
                {currentThreat.severity}
              </span>
              {currentThreat.mitre_id && (
                <span className="px-2 py-0.5 rounded-md text-[11px] font-mono font-semibold text-slate-600 bg-slate-100">
                  {currentThreat.mitre_id}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 mt-1">
              {currentThreat.indicator ? `Indicator: ${currentThreat.indicator}` : `Targeting ${currentThreat.dest_ip}`}
            </p>
          </div>
        </div>

        {/* Confidence & First Seen Metrics */}
        <div className="flex items-center gap-8 text-xs font-sans">
          <div>
            <span className="text-slate-400 font-medium block">ML Confidence</span>
            <span className="text-xl font-bold text-slate-900 block mt-0.5 font-mono">
              {currentThreat.confidence}
            </span>
          </div>

          <div>
            <span className="text-slate-400 font-medium block">First Seen</span>
            <span className="font-bold text-slate-900 block mt-0.5 font-mono">
              {currentThreat.first_seen}
            </span>
            <span className="text-[11px] text-slate-400 block">
              Live Session
            </span>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center gap-6 border-b border-slate-200 text-xs font-medium overflow-x-auto">
        {subTabs.map((tab) => (
          <button
            key={tab}
            onClick={() => {
              setActiveSubTab(tab);
              if (tab === 'Attack Timeline' && onSelectTab) onSelectTab('timeline');
              if (tab === 'Network Graph' && onSelectTab) onSelectTab('graph');
              if (tab === 'AI Explanation' && onSelectTab) onSelectTab('explainability');
              if (tab === 'MITRE ATT&CK' && onSelectTab) onSelectTab('mitre');
              if (tab === 'Raw Logs' && onSelectTab) onSelectTab('loganalysis');
            }}
            className={`pb-3 cursor-pointer transition-colors relative whitespace-nowrap ${
              activeSubTab === tab
                ? 'text-blue-600 font-semibold'
                : 'text-slate-500 hover:text-slate-900'
            }`}
          >
            {tab}
            {activeSubTab === tab && (
              <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-600 rounded-full" />
            )}
          </button>
        ))}
      </div>

      {/* 2-Column Grid Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Left Column: Attack Details & Why Was This Detected? */}
        <div className="space-y-6">
          {/* Attack Details Card */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs">
            <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight pb-3 border-b border-slate-100 mb-3">
              Attack Details
            </h3>

            <div className="space-y-2.5 text-xs font-sans">
              <div className="flex items-center justify-between py-1">
                <span className="text-slate-500">Source IP</span>
                <span className="font-semibold text-slate-900 font-mono">{currentThreat.source_ip}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">Destination IP</span>
                <span className="font-semibold text-slate-900 font-mono">{currentThreat.dest_ip}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">Attack Type</span>
                <span className="font-semibold text-slate-900">{currentThreat.name}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">Severity</span>
                <span className="font-bold text-red-600">{currentThreat.severity}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">ML Confidence</span>
                <span className="font-semibold text-slate-900 font-mono">{currentThreat.confidence}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">First Seen</span>
                <span className="font-semibold text-slate-900 font-mono">{currentThreat.first_seen}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">Last Seen</span>
                <span className="font-semibold text-slate-900 font-mono">{currentThreat.last_seen}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">Duration</span>
                <span className="font-semibold text-slate-900">{currentThreat.duration}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">Events Logged</span>
                <span className="font-semibold text-slate-900 font-mono">{currentThreat.event_count}</span>
              </div>
            </div>
          </div>

          {/* Why Was This Detected? Card */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs">
            <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight pb-3 border-b border-slate-100 mb-3">
              Why Was This Detected? (Feature Attribution)
            </h3>

            <ul className="space-y-2.5 text-xs text-slate-700 font-sans">
              {(currentThreat.why_detected || []).map((reason, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-400 mt-1.5 shrink-0" />
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Right Column: Traffic Pattern & Recommended Actions */}
        <div className="space-y-6">
          {/* Traffic Pattern Area Chart Card */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-3">
              <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight">
                Traffic Pattern Analysis
              </h3>

              <div className="flex items-center gap-4 text-xs font-medium">
                <div className="flex items-center gap-1.5 text-blue-600">
                  <span className="w-3 h-0.5 bg-blue-600 rounded-full" />
                  <span className="text-slate-600">Normal</span>
                </div>
                <div className="flex items-center gap-1.5 text-red-500">
                  <span className="w-3 h-0.5 bg-red-500 rounded-full" />
                  <span className="text-slate-600">Attack Flow</span>
                </div>
              </div>
            </div>

            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={currentThreat.traffic_pattern || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="attackSpike" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                  <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} />
                  <YAxis stroke="#94a3b8" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '0.375rem', fontSize: '12px' }} />
                  <Area type="monotone" dataKey="normal" stroke="#3b82f6" strokeWidth={1.5} fill="none" />
                  <Area type="monotone" dataKey="attack" stroke="#ef4444" strokeWidth={2.5} fillOpacity={1} fill="url(#attackSpike)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Recommended Actions Card */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs">
            <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight pb-3 border-b border-slate-100 mb-3">
              Recommended Mitigation Actions
            </h3>

            <div className="space-y-3 font-sans">
              {(currentThreat.recommended_actions || []).map((action, idx) => (
                <div key={idx} className="flex items-start justify-between p-3 rounded-lg border border-slate-100 hover:border-slate-200 bg-slate-50/50 text-xs">
                  <div className="flex items-start gap-2.5">
                    <span className="w-5 h-5 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">
                      {idx + 1}
                    </span>
                    <div>
                      <p className="font-semibold text-slate-900">{action}</p>
                      <p className="text-[11px] text-slate-500 mt-0.5">Automated mitigation rule candidate</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setActionTaken(true)}
                    className="px-2.5 py-1 text-[11px] font-semibold text-blue-600 bg-white border border-blue-200 rounded hover:bg-blue-50 transition cursor-pointer shrink-0"
                  >
                    Execute
                  </button>
                </div>
              ))}

              {actionTaken && (
                <div className="mt-2 p-2.5 bg-emerald-50 border border-emerald-200 rounded-lg flex items-center gap-2 text-xs text-emerald-800">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  <span>Mitigation playbook sent to API Gateway & Ingress Router.</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
