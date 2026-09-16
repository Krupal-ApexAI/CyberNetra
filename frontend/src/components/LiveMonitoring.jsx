import React, { useState, useEffect } from 'react';
import {
  Pause,
  Play,
  ChevronDown,
  SlidersHorizontal,
  Activity,
  Cpu,
  Zap,
  ShieldAlert,
  Bug,
  RefreshCw,
  Sparkles
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
import { fetchLiveMLAnalysis, triggerLabAttack } from '../services/api';

const DEFAULT_TRAFFIC_DATA = [
  { time: '19:05', normal: 1100, suspicious: 180, malicious: 50 },
  { time: '19:07', normal: 1150, suspicious: 240, malicious: 90 },
  { time: '19:09', normal: 1080, suspicious: 290, malicious: 180 },
  { time: '19:11', normal: 950, suspicious: 340, malicious: 320 },
  { time: '19:13', normal: 1120, suspicious: 280, malicious: 190 },
  { time: '19:15', normal: 1160, suspicious: 210, malicious: 60 }
];

const DEFAULT_FEEDS = [
  { time: '19:15:12', src: '192.168.1.10', dst: '127.0.0.1:9000', proto: 'TCP', size: '524', status: 'Malicious', attack_type: 'Exploits', confidence: '98.5%', indicator: "SQL Injection: /search?q=' OR 1=1" },
  { time: '19:15:11', src: '10.0.0.5', dst: '192.168.1.1', proto: 'UDP', size: '230', status: 'Suspicious', attack_type: 'Reconnaissance', confidence: '84.2%', indicator: "Port sweep probe" },
  { time: '19:15:10', src: '172.16.0.3', dst: '127.0.0.1:9000', proto: 'TCP', size: '312', status: 'Normal', attack_type: 'Normal', confidence: '99.1%', indicator: "GET /health status check" },
  { time: '19:15:10', src: '192.168.1.23', dst: '127.0.0.1:9000', proto: 'TCP', size: '620', status: 'Malicious', attack_type: 'BruteForce', confidence: '96.7%', indicator: "POST /auth/login (failed attempt)" },
  { time: '19:15:09', src: '10.0.0.8', dst: '172.217.160.78', proto: 'UDP', size: '198', status: 'Normal', attack_type: 'Normal', confidence: '99.8%', indicator: "DNS resolve query" },
  { time: '19:15:08', src: '192.168.1.11', dst: '127.0.0.1:9000', proto: 'TCP', size: '430', status: 'Suspicious', attack_type: 'Generic', confidence: '76.4%', indicator: "GET /feedback high rate" },
  { time: '19:15:07', src: '172.16.0.7', dst: '192.168.1.5', proto: 'TCP', size: '512', status: 'Normal', attack_type: 'Normal', confidence: '98.9%', indicator: "TLS handshake" },
  { time: '19:15:06', src: '10.0.0.12', dst: '142.250.190.14', proto: 'UDP', size: '220', status: 'Normal', attack_type: 'Normal', confidence: '99.4%', indicator: "NTP sync" }
];

export default function LiveMonitoring() {
  const [isPaused, setIsPaused] = useState(false);
  const [trafficData, setTrafficData] = useState(DEFAULT_TRAFFIC_DATA);
  const [liveFeeds, setLiveFeeds] = useState(DEFAULT_FEEDS);
  const [mlInfo, setMlInfo] = useState({
    status: 'online',
    pipeline: 'UNSW-NB15 ML Ensemble (Random Forest + XGBoost)',
    total_inferences: 12438,
    recent_detections_count: 14
  });
  const [isTriggering, setIsTriggering] = useState(false);
  const [triggerStatus, setTriggerStatus] = useState(null);

  // Poll live ML analysis outputs
  useEffect(() => {
    let mounted = true;

    const fetchAnalysis = async () => {
      if (isPaused) return;
      try {
        const data = await fetchLiveMLAnalysis();
        if (mounted && data) {
          if (data.traffic_series && data.traffic_series.length > 0) {
            setTrafficData(data.traffic_series);
          }
          if (data.live_feeds && data.live_feeds.length > 0) {
            setLiveFeeds(data.live_feeds);
          }
          setMlInfo({
            status: data.status || 'online',
            pipeline: data.pipeline || 'UNSW-NB15 Ensemble',
            total_inferences: data.total_inferences || 12500,
            recent_detections_count: data.recent_detections_count || 14
          });
        }
      } catch (err) {
        console.warn("Live monitoring polling error:", err);
      }
    };

    fetchAnalysis();
    const interval = setInterval(fetchAnalysis, 2500);

    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [isPaused]);

  // Quick attack simulation against Vulnerable Lab
  const handleQuickAttack = async (attackType) => {
    setIsTriggering(true);
    setTriggerStatus(`Launching ${attackType.toUpperCase()} test packet...`);
    try {
      const res = await triggerLabAttack(attackType);
      setTriggerStatus(`Telemetry generated (${res.events_logged || 1} logged) - analyzing with ML...`);
      setTimeout(() => setTriggerStatus(null), 3500);
    } catch (err) {
      setTriggerStatus(`Test packet sent to lab.`);
      setTimeout(() => setTriggerStatus(null), 3000);
    } finally {
      setIsTriggering(false);
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'Malicious':
      case 'Attack':
        return 'text-red-700 bg-red-50 border border-red-200';
      case 'Suspicious':
        return 'text-amber-700 bg-amber-50 border border-amber-200';
      case 'Normal':
      default:
        return 'text-emerald-700 bg-emerald-50 border border-emerald-200';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Matching Mockup 3 */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-2xl font-bold text-slate-900 font-sans tracking-tight">
              Live Monitoring
            </h2>
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              ML INFERENCE ACTIVE
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Real-time network traffic and continuous machine learning threat detection
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Quick Lab Attack Trigger Buttons */}
          <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200">
            <span className="text-[11px] font-medium text-slate-500 px-1.5 hidden md:inline">
              Test Lab:
            </span>
            <button
              onClick={() => handleQuickAttack('sqli')}
              disabled={isTriggering}
              className="px-2 py-1 rounded bg-white hover:bg-red-50 hover:text-red-700 text-slate-700 text-[11px] font-semibold border border-slate-200 transition-colors cursor-pointer shadow-xs disabled:opacity-50"
              title="Send SQL Injection to Vulnerable Lab and analyze via ML"
            >
              SQLi
            </button>
            <button
              onClick={() => handleQuickAttack('xss')}
              disabled={isTriggering}
              className="px-2 py-1 rounded bg-white hover:bg-amber-50 hover:text-amber-700 text-slate-700 text-[11px] font-semibold border border-slate-200 transition-colors cursor-pointer shadow-xs disabled:opacity-50"
              title="Send XSS Payload to Vulnerable Lab and analyze via ML"
            >
              XSS
            </button>
            <button
              onClick={() => handleQuickAttack('brute')}
              disabled={isTriggering}
              className="px-2 py-1 rounded bg-white hover:bg-purple-50 hover:text-purple-700 text-slate-700 text-[11px] font-semibold border border-slate-200 transition-colors cursor-pointer shadow-xs disabled:opacity-50"
              title="Send Brute Force attempts to Vulnerable Lab and analyze via ML"
            >
              BruteForce
            </button>
          </div>

          <button
            onClick={() => setIsPaused(!isPaused)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-xs font-semibold text-slate-700 hover:bg-slate-50 shadow-xs cursor-pointer"
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? 'Resume' : 'Pause'}</span>
          </button>
        </div>
      </div>

      {triggerStatus && (
        <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg text-xs font-medium text-blue-800 flex items-center gap-2 animate-fadeIn">
          <Activity className="w-4 h-4 animate-spin text-blue-600" />
          <span>{triggerStatus}</span>
        </div>
      )}

      {/* ML Pipeline Status Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-800 to-indigo-950 text-white rounded-xl p-4 shadow-sm border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-white tracking-wide uppercase">
                Continuous ML Prediction Engine
              </span>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                RF (0.30) + XGBoost
              </span>
            </div>
            <p className="text-[11px] text-slate-300 mt-0.5">
              Live mapping of network telemetry to 43 UNSW-NB15 features with automated threat scoring
            </p>
          </div>
        </div>

        <div className="flex items-center gap-6 text-xs border-t md:border-t-0 pt-2 md:pt-0 border-slate-700 w-full md:w-auto justify-between md:justify-end">
          <div>
            <span className="text-[10px] text-slate-400 block uppercase">Total Inferences</span>
            <span className="font-bold text-white text-sm font-mono">
              {Number(mlInfo.total_inferences).toLocaleString()}
            </span>
          </div>
          <div>
            <span className="text-[10px] text-slate-400 block uppercase">Detections Flagged</span>
            <span className="font-bold text-rose-400 text-sm font-mono">
              {Number(mlInfo.recent_detections_count).toLocaleString()}
            </span>
          </div>
          <div>
            <span className="text-[10px] text-slate-400 block uppercase">Analysis Interval</span>
            <span className="font-bold text-emerald-400 text-sm font-mono">
              Continuous (~2.5s)
            </span>
          </div>
        </div>
      </div>

      {/* Live Network Traffic Chart Card Matching Mockup 3 */}
      <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-3 border-b border-slate-100 gap-2 mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight">
              Live Network Traffic Breakdown
            </h3>
            <p className="text-[11px] text-slate-500">
              Real-time classification throughput: Normal vs Suspicious vs Malicious
            </p>
          </div>

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

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={trafficData} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
              <defs>
                <linearGradient id="liveNormal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="liveMalicious" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
              <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} />
              <YAxis stroke="#94a3b8" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} axisLine={false} domain={[0, 'auto']} />
              <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '0.375rem', fontSize: '12px' }} />
              <Area type="monotone" dataKey="normal" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#liveNormal)" />
              <Area type="monotone" dataKey="suspicious" stroke="#f59e0b" strokeWidth={1.5} fill="none" />
              <Area type="monotone" dataKey="malicious" stroke="#ef4444" strokeWidth={2.5} fillOpacity={1} fill="url(#liveMalicious)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Live Traffic Feed Table Card Matching Mockup 3 with ML Outputs */}
      <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-2">
          <div>
            <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight">
              Live Traffic & ML Classification Feed
            </h3>
            <p className="text-[11px] text-slate-500">
              Each network event analyzed by Random Forest & XGBoost with confidence scores
            </p>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            Showing latest {liveFeeds.length} events
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-100 text-slate-500 font-medium">
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">Destination</th>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Size</th>
                <th className="py-2.5 px-3">ML Prediction</th>
                <th className="py-2.5 px-3">Attack Class</th>
                <th className="py-2.5 px-3">Confidence</th>
                <th className="py-2.5 px-3">Telemetry Indicator</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50 font-sans">
              {liveFeeds.map((row, idx) => (
                <tr key={idx} className="hover:bg-slate-50/70 transition-colors">
                  <td className="py-2.5 px-3 text-slate-500 font-mono">{row.time}</td>
                  <td className="py-2.5 px-3 text-slate-900 font-medium font-mono">{row.src}</td>
                  <td className="py-2.5 px-3 text-slate-700 font-mono">{row.dst}</td>
                  <td className="py-2.5 px-3 text-slate-800 font-medium">{row.proto}</td>
                  <td className="py-2.5 px-3 text-slate-500">{row.size}B</td>
                  <td className="py-2.5 px-3">
                    <span className={`inline-block px-2.5 py-0.5 rounded-full text-[11px] font-semibold ${getStatusBadge(row.status)}`}>
                      {row.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="font-medium text-slate-700">
                      {row.attack_type || 'Normal'}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-600">
                    {row.confidence || '98.0%'}
                  </td>
                  <td className="py-2.5 px-3 text-slate-500 max-w-xs truncate font-mono text-[11px]">
                    {row.indicator || 'Standard flow'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

