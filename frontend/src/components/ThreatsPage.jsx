import React, { useState } from 'react';
import {
  ShieldAlert,
  Download,
  CheckCircle2
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

export default function ThreatsPage({ onSelectTab }) {
  const [activeSubTab, setActiveSubTab] = useState('Overview');
  const [actionTaken, setActionTaken] = useState(false);

  const trafficData = [
    { time: '10:20', normal: 120, attack: 10 },
    { time: '10:21', normal: 135, attack: 20 },
    { time: '10:22', normal: 125, attack: 50 },
    { time: '10:23', normal: 110, attack: 680 },
    { time: '10:24', normal: 95, attack: 1840 },
    { time: '10:25', normal: 130, attack: 720 },
    { time: '10:26', normal: 140, attack: 150 }
  ];

  const subTabs = [
    'Overview',
    'Attack Timeline',
    'Network Graph',
    'AI Explanation',
    'MITRE ATT&CK',
    'Raw Logs'
  ];

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb & Export Button Matching Mockup 4 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs text-slate-500 font-medium">
          <span className="cursor-pointer hover:text-slate-800">Threats</span>
          <span>/</span>
          <span className="text-slate-900 font-semibold">DDoS Attack</span>
        </div>

        <button className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-slate-50 text-xs font-semibold text-slate-700 shadow-xs cursor-pointer">
          <Download className="w-3.5 h-3.5" />
          <span>Export Report</span>
        </button>
      </div>

      {/* Threat Summary Banner Card Matching Mockup 4 */}
      <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-red-50 border border-red-100 flex items-center justify-center shrink-0">
            <ShieldAlert className="w-6 h-6 text-red-500" />
          </div>

          <div>
            <div className="flex items-center gap-2.5">
              <h2 className="text-lg font-bold text-slate-900 font-sans">
                DDoS Attack
              </h2>
              <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold text-red-700 bg-red-50 border border-red-200">
                Critical
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              High volume of SYN packets targeting 8.8.8.8
            </p>
          </div>
        </div>

        {/* Confidence & First Seen Metrics */}
        <div className="flex items-center gap-8 text-xs font-sans">
          <div>
            <span className="text-slate-400 font-medium block">Confidence</span>
            <span className="text-xl font-bold text-slate-900 block mt-0.5">
              98%
            </span>
          </div>

          <div>
            <span className="text-slate-400 font-medium block">First Seen</span>
            <span className="font-bold text-slate-900 block mt-0.5">
              10:23:41
            </span>
            <span className="text-[11px] text-slate-400 block">
              11 Sept 2026
            </span>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs Matching Mockup 4 */}
      <div className="flex items-center gap-6 border-b border-slate-200 text-xs font-medium">
        {subTabs.map((tab) => (
          <button
            key={tab}
            onClick={() => {
              setActiveSubTab(tab);
              if (tab === 'Attack Timeline' && onSelectTab) onSelectTab('timeline');
              if (tab === 'Network Graph' && onSelectTab) onSelectTab('graph');
              if (tab === 'AI Explanation' && onSelectTab) onSelectTab('explainability');
              if (tab === 'MITRE ATT&CK' && onSelectTab) onSelectTab('mitre');
            }}
            className={`pb-3 cursor-pointer transition-colors relative ${
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

      {/* 2-Column Grid Layout Matching Mockup 4 */}
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
                <span className="font-semibold text-slate-900">192.168.1.10</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">Destination IP</span>
                <span className="font-semibold text-slate-900">8.8.8.8</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">Protocol</span>
                <span className="font-semibold text-slate-900">TCP</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">Severity</span>
                <span className="font-bold text-red-600">Critical</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">Confidence</span>
                <span className="font-semibold text-slate-900">98%</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">First Seen</span>
                <span className="font-semibold text-slate-900">10:23:41</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">Last Seen</span>
                <span className="font-semibold text-slate-900">10:24:17</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">Duration</span>
                <span className="font-semibold text-slate-900">36 seconds</span>
              </div>
              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-500">Total Packets</span>
                <span className="font-semibold text-slate-900">12,430</span>
              </div>
            </div>
          </div>

          {/* Why Was This Detected? Card */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs">
            <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight pb-3 border-b border-slate-100 mb-3">
              Why Was This Detected?
            </h3>

            <ul className="space-y-2.5 text-xs text-slate-700 font-sans">
              <li className="flex items-start gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400 mt-1.5 shrink-0" />
                <span>Unusually high number of SYN packets</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400 mt-1.5 shrink-0" />
                <span>Traffic rate significantly above baseline</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400 mt-1.5 shrink-0" />
                <span>Repeated requests from single source</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400 mt-1.5 shrink-0" />
                <span>Pattern matches known DDoS behavior (trained on UNSW-NB15 & CTU-13)</span>
              </li>
            </ul>
          </div>
        </div>

        {/* Right Column: Traffic Pattern & Recommended Actions */}
        <div className="space-y-6">
          {/* Traffic Pattern Area Chart Card */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-3">
              <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight">
                Traffic Pattern
              </h3>

              <div className="flex items-center gap-4 text-xs font-medium">
                <div className="flex items-center gap-1.5 text-blue-600">
                  <span className="w-3 h-0.5 bg-blue-600 rounded-full" />
                  <span className="text-slate-600">Normal</span>
                </div>
                <div className="flex items-center gap-1.5 text-red-500">
                  <span className="w-3 h-0.5 bg-red-500 rounded-full" />
                  <span className="text-slate-600">Attack Traffic</span>
                </div>
              </div>
            </div>

            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="attackSpike" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                  <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} />
                  <YAxis stroke="#94a3b8" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} axisLine={false} domain={[0, 2000]} ticks={[0, 500, 1000, 1500, 2000]} />
                  <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '0.375rem', fontSize: '12px' }} />
                  <Area type="monotone" dataKey="normal" stroke="#3b82f6" strokeWidth={1.5} fill="none" />
                  <Area type="monotone" dataKey="attack" stroke="#ef4444" strokeWidth={2.5} fillOpacity={1} fill="url(#attackSpike)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Recommended Actions Card */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs flex flex-col justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight pb-3 border-b border-slate-100 mb-3">
                Recommended Actions
              </h3>

              <div className="space-y-3 text-xs text-slate-700 font-sans">
                <div className="flex items-start gap-2.5">
                  <span className="w-5 h-5 rounded-full bg-slate-100 text-slate-700 font-semibold flex items-center justify-center shrink-0 text-[11px]">
                    1
                  </span>
                  <span className="mt-0.5">Block or rate-limit traffic from 192.168.1.10</span>
                </div>
                <div className="flex items-start gap-2.5">
                  <span className="w-5 h-5 rounded-full bg-slate-100 text-slate-700 font-semibold flex items-center justify-center shrink-0 text-[11px]">
                    2
                  </span>
                  <span className="mt-0.5">Monitor for similar behavior from related IPs</span>
                </div>
                <div className="flex items-start gap-2.5">
                  <span className="w-5 h-5 rounded-full bg-slate-100 text-slate-700 font-semibold flex items-center justify-center shrink-0 text-[11px]">
                    3
                  </span>
                  <span className="mt-0.5">Investigate if the source is part of a larger botnet</span>
                </div>
              </div>
            </div>

            {/* Take Action CTA Button */}
            <div className="mt-6 pt-4 border-t border-slate-100">
              <button
                onClick={() => setActionTaken(!actionTaken)}
                className={`w-full py-2.5 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center justify-center gap-2 ${
                  actionTaken
                    ? 'bg-emerald-600 text-white'
                    : 'bg-[#0f172a] hover:bg-[#1e293b] text-white shadow-xs'
                }`}
              >
                {actionTaken ? (
                  <>
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Mitigation Applied Successfully</span>
                  </>
                ) : (
                  <span>Take Action →</span>
                )}
              </button>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
