import React, { useState, useEffect, useCallback } from 'react';
import {
  FlaskConical,
  Shield,
  Wifi,
  WifiOff,
  Zap,
  Bug,
  Code,
  FolderOpen,
  Terminal,
  KeyRound,
  Waves,
  Activity,
  Clock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Loader2,
  Server,
  ArrowUpRight
} from 'lucide-react';

import {
  fetchLabStatus,
  triggerLabAttack,
  fetchLabEvents,
} from '../services/api';

// ── Attack surface definitions ──
const ATTACK_SURFACES = [
  {
    id: 'sqli',
    name: 'SQL Injection',
    icon: Bug,
    mitre: 'T1190',
    color: '#f43f5e',
    bgColor: 'rgba(244,63,94,0.08)',
    borderColor: 'rgba(244,63,94,0.25)',
    description: 'Inject SQL payloads to bypass auth and dump records',
    endpoint: "GET /api/users?search=' OR '1'='1",
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting',
    icon: Code,
    mitre: 'T1059.007',
    color: '#f59e0b',
    bgColor: 'rgba(245,158,11,0.08)',
    borderColor: 'rgba(245,158,11,0.25)',
    description: 'Inject script payloads via reflected and stored fields',
    endpoint: "GET /search?q=<script>alert(1)</script>",
  },
  {
    id: 'traversal',
    name: 'Path Traversal',
    icon: FolderOpen,
    mitre: 'T1083',
    color: '#8b5cf6',
    bgColor: 'rgba(139,92,246,0.08)',
    borderColor: 'rgba(139,92,246,0.25)',
    description: 'Read sensitive files by escaping the web root',
    endpoint: "GET /api/logs/view?file=../../etc/passwd",
  },
  {
    id: 'cmd',
    name: 'Command Injection',
    icon: Terminal,
    mitre: 'T1059',
    color: '#06b6d4',
    bgColor: 'rgba(6,182,212,0.08)',
    borderColor: 'rgba(6,182,212,0.25)',
    description: 'Execute OS commands via diagnostic utilities',
    endpoint: "POST /api/tools/ping {host: '127.0.0.1; whoami'}",
  },
  {
    id: 'brute',
    name: 'Brute Force Login',
    icon: KeyRound,
    mitre: 'T1110',
    color: '#ec4899',
    bgColor: 'rgba(236,72,153,0.08)',
    borderColor: 'rgba(236,72,153,0.25)',
    description: 'Rapid credential spraying against login endpoint',
    endpoint: "POST /auth/login (5 rapid attempts)",
  },
  {
    id: 'dos',
    name: 'Denial of Service',
    icon: Waves,
    mitre: 'T1498',
    color: '#ef4444',
    bgColor: 'rgba(239,68,68,0.08)',
    borderColor: 'rgba(239,68,68,0.25)',
    description: 'Flood resource-intensive endpoint for DoS simulation',
    endpoint: "GET /api/resource-intensive (10 rapid floods)",
  },
];

// ── Event type badge colors ──
function getEventBadge(eventType) {
  switch (eventType) {
    case 'suspicious_input':
      return { bg: 'bg-rose-50', text: 'text-rose-700', border: 'border-rose-200', label: 'ATTACK' };
    case 'auth_failure':
      return { bg: 'bg-amber-50', text: 'text-amber-700', border: 'border-amber-200', label: 'AUTH FAIL' };
    case 'rate_limit':
      return { bg: 'bg-red-50', text: 'text-red-700', border: 'border-red-200', label: 'RATE LIMIT' };
    case 'path_scan':
      return { bg: 'bg-purple-50', text: 'text-purple-700', border: 'border-purple-200', label: 'SCAN' };
    default:
      return { bg: 'bg-emerald-50', text: 'text-emerald-700', border: 'border-emerald-200', label: 'NORMAL' };
  }
}

function formatTime(isoStr) {
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return '--:--:--';
  }
}

export default function VulnerableLab() {
  const [labStatus, setLabStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [attackStates, setAttackStates] = useState({});
  const [attackResults, setAttackResults] = useState({});
  const [expandedAttack, setExpandedAttack] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  // Fetch lab status
  const loadStatus = useCallback(async () => {
    try {
      const data = await fetchLabStatus();
      setLabStatus(data);
    } catch {
      setLabStatus({ connection: 'disconnected', status: 'offline' });
    }
  }, []);

  // Fetch lab events
  const loadEvents = useCallback(async () => {
    try {
      const data = await fetchLabEvents(40);
      if (data && data.events) {
        setEvents(data.events);
      }
    } catch {
      // Keep existing events
    }
  }, []);

  // Initial load
  useEffect(() => {
    const init = async () => {
      setLoading(true);
      await Promise.all([loadStatus(), loadEvents()]);
      setLoading(false);
    };
    init();
  }, [loadStatus, loadEvents]);

  // Auto-refresh every 4 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      loadStatus();
      loadEvents();
    }, 4000);
    return () => clearInterval(interval);
  }, [loadStatus, loadEvents]);

  // Manual refresh
  const handleRefresh = async () => {
    setRefreshing(true);
    await Promise.all([loadStatus(), loadEvents()]);
    setTimeout(() => setRefreshing(false), 500);
  };

  // Fire an attack
  const handleAttack = async (attackId) => {
    setAttackStates(prev => ({ ...prev, [attackId]: 'loading' }));
    setAttackResults(prev => ({ ...prev, [attackId]: null }));
    setExpandedAttack(attackId);

    try {
      const result = await triggerLabAttack(attackId);
      setAttackResults(prev => ({ ...prev, [attackId]: { success: true, data: result } }));
      setAttackStates(prev => ({ ...prev, [attackId]: 'done' }));
      // Refresh events after attack
      setTimeout(() => {
        loadEvents();
        loadStatus();
      }, 1500);
    } catch (err) {
      setAttackResults(prev => ({
        ...prev,
        [attackId]: { success: false, error: err.message || 'Attack failed' },
      }));
      setAttackStates(prev => ({ ...prev, [attackId]: 'error' }));
    }
  };

  const isOnline = labStatus?.connection === 'connected';

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
        <span className="ml-3 text-sm text-slate-500">Connecting to Vulnerable Lab...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight flex items-center gap-2.5">
            <FlaskConical className="w-6 h-6 text-violet-500" />
            Vulnerable Lab
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Controlled security testing sandbox — all activity generates telemetry for CyberNetra AI
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleRefresh}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-xs font-medium text-slate-600 hover:bg-slate-50 shadow-xs cursor-pointer transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <a
            href="http://127.0.0.1:9000"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-violet-50 border border-violet-200 text-xs font-medium text-violet-700 hover:bg-violet-100 shadow-xs cursor-pointer transition-colors"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            Open Lab Portal
          </a>
        </div>
      </div>

      {/* Connection Status Banner */}
      <div
        className={`rounded-xl border px-5 py-4 flex items-center justify-between transition-all ${
          isOnline
            ? 'bg-emerald-50/60 border-emerald-200'
            : 'bg-red-50/60 border-red-200'
        }`}
      >
        <div className="flex items-center gap-3">
          {isOnline ? (
            <>
              <div className="w-9 h-9 rounded-full bg-emerald-100 flex items-center justify-center">
                <Wifi className="w-4.5 h-4.5 text-emerald-600" />
              </div>
              <div>
                <p className="text-sm font-semibold text-emerald-800">Lab Connected & Active</p>
                <p className="text-xs text-emerald-600">
                  Port 9000 • Uptime: {Math.round((labStatus?.uptime_seconds || 0) / 60)}min •{' '}
                  {labStatus?.total_events || 0} events captured
                </p>
              </div>
            </>
          ) : (
            <>
              <div className="w-9 h-9 rounded-full bg-red-100 flex items-center justify-center">
                <WifiOff className="w-4.5 h-4.5 text-red-600" />
              </div>
              <div>
                <p className="text-sm font-semibold text-red-800">Lab Disconnected</p>
                <p className="text-xs text-red-600">
                  Start the lab: <code className="bg-red-100 px-1.5 py-0.5 rounded text-[11px]">python -m uvicorn app.main:app --port 9000</code>
                </p>
              </div>
            </>
          )}
        </div>

        {isOnline && (
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-lg font-bold text-emerald-800">{labStatus?.attack_events || 0}</p>
              <p className="text-[10px] text-emerald-600 font-medium">ATTACK EVENTS</p>
            </div>
            <div className="w-px h-8 bg-emerald-200" />
            <div className="text-right">
              <p className="text-lg font-bold text-emerald-800">{labStatus?.normal_events || 0}</p>
              <p className="text-[10px] text-emerald-600 font-medium">NORMAL EVENTS</p>
            </div>
          </div>
        )}
      </div>

      {/* Stats Row (only when connected) */}
      {isOnline && labStatus?.attack_surface_counts && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
          {[
            { label: 'SQLi', count: labStatus.attack_surface_counts.sqli || 0, color: '#f43f5e' },
            { label: 'XSS', count: labStatus.attack_surface_counts.xss || 0, color: '#f59e0b' },
            { label: 'Traversal', count: labStatus.attack_surface_counts.traversal || 0, color: '#8b5cf6' },
            { label: 'CMD Inj.', count: labStatus.attack_surface_counts.cmd_injection || 0, color: '#06b6d4' },
            { label: 'Brute Force', count: labStatus.attack_surface_counts.brute_force || 0, color: '#ec4899' },
            { label: 'DoS', count: labStatus.attack_surface_counts.dos || 0, color: '#ef4444' },
            { label: 'Recon', count: labStatus.attack_surface_counts.recon || 0, color: '#6366f1' },
          ].map((stat) => (
            <div
              key={stat.label}
              className="bg-white rounded-lg border border-slate-200 p-3 text-center shadow-xs"
            >
              <p className="text-xl font-bold" style={{ color: stat.count > 0 ? stat.color : '#94a3b8' }}>
                {stat.count}
              </p>
              <p className="text-[10px] font-medium text-slate-500 mt-0.5">{stat.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Left Column: Attack Console (3/5) */}
        <div className="lg:col-span-3 space-y-4">
          <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-amber-500" />
                <h2 className="text-sm font-semibold text-slate-800">Attack Console</h2>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 font-medium">
                  6 Vulnerability Surfaces
                </span>
              </div>
            </div>

            <div className="p-4 space-y-3">
              {ATTACK_SURFACES.map((attack) => {
                const Icon = attack.icon;
                const state = attackStates[attack.id];
                const result = attackResults[attack.id];
                const isExpanded = expandedAttack === attack.id;

                return (
                  <div
                    key={attack.id}
                    className="rounded-lg border transition-all"
                    style={{
                      borderColor: state === 'done' ? attack.borderColor : '#e2e8f0',
                      backgroundColor: state === 'done' ? attack.bgColor : '#ffffff',
                    }}
                  >
                    <div className="flex items-center justify-between px-4 py-3">
                      <div className="flex items-center gap-3 min-w-0">
                        <div
                          className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                          style={{ backgroundColor: attack.bgColor }}
                        >
                          <Icon className="w-4 h-4" style={{ color: attack.color }} />
                        </div>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <p className="text-xs font-semibold text-slate-800">{attack.name}</p>
                            <span
                              className="text-[9px] px-1.5 py-0.5 rounded font-mono font-semibold"
                              style={{ backgroundColor: attack.bgColor, color: attack.color }}
                            >
                              {attack.mitre}
                            </span>
                          </div>
                          <p className="text-[10px] text-slate-500 truncate">{attack.description}</p>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          onClick={() => handleAttack(attack.id)}
                          disabled={state === 'loading' || !isOnline}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                            !isOnline
                              ? 'bg-slate-100 text-slate-400 cursor-not-allowed'
                              : state === 'loading'
                              ? 'bg-slate-100 text-slate-500'
                              : 'bg-slate-900 text-white hover:bg-slate-800 shadow-sm'
                          }`}
                        >
                          {state === 'loading' ? (
                            <Loader2 className="w-3 h-3 animate-spin" />
                          ) : (
                            <Zap className="w-3 h-3" />
                          )}
                          {state === 'loading' ? 'Executing...' : 'Fire'}
                        </button>
                        {result && (
                          <button
                            onClick={() => setExpandedAttack(isExpanded ? null : attack.id)}
                            className="p-1 rounded hover:bg-slate-100 cursor-pointer"
                          >
                            {isExpanded ? (
                              <ChevronDown className="w-4 h-4 text-slate-400" />
                            ) : (
                              <ChevronRight className="w-4 h-4 text-slate-400" />
                            )}
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Expanded result */}
                    {isExpanded && result && (
                      <div className="px-4 pb-3 border-t border-slate-100">
                        {result.success ? (
                          <div className="mt-3 space-y-2">
                            <div className="flex items-center gap-2">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                              <span className="text-xs font-medium text-emerald-700">
                                Attack executed — telemetry captured by CyberNetra
                              </span>
                            </div>
                            <pre className="text-[10px] bg-slate-50 border border-slate-200 rounded-lg p-3 max-h-48 overflow-auto text-slate-600 font-mono leading-relaxed">
                              {JSON.stringify(result.data, null, 2)}
                            </pre>
                          </div>
                        ) : (
                          <div className="mt-3 flex items-center gap-2">
                            <XCircle className="w-3.5 h-3.5 text-red-500" />
                            <span className="text-xs text-red-600">{result.error}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Column: Live Event Feed (2/5) */}
        <div className="lg:col-span-2">
          <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-blue-500" />
                <h2 className="text-sm font-semibold text-slate-800">Live Telemetry Feed</h2>
                {events.length > 0 && (
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-50 text-blue-600 font-medium">
                    {events.length} events
                  </span>
                )}
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-[10px] text-slate-400">Auto-refresh</span>
              </div>
            </div>

            <div className="max-h-[600px] overflow-y-auto">
              {events.length === 0 ? (
                <div className="p-8 text-center">
                  <Server className="w-8 h-8 text-slate-300 mx-auto mb-3" />
                  <p className="text-xs text-slate-400">
                    {isOnline
                      ? 'No events yet — trigger an attack to generate telemetry'
                      : 'Connect the lab to see live events'}
                  </p>
                </div>
              ) : (
                <div className="divide-y divide-slate-50">
                  {events.map((item, idx) => {
                    const event = item.raw || item;
                    const badge = getEventBadge(event.event_type);
                    const classification = item.classification;

                    return (
                      <div
                        key={idx}
                        className="px-4 py-2.5 hover:bg-slate-50/50 transition-colors"
                      >
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <span className={`text-[9px] px-1.5 py-0.5 rounded border font-semibold ${badge.bg} ${badge.text} ${badge.border}`}>
                              {badge.label}
                            </span>
                            {event.mitre_technique && (
                              <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 font-mono font-medium">
                                {event.mitre_technique}
                              </span>
                            )}
                            {classification && classification !== 'Normal' && (
                              <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-50 text-red-600 font-semibold border border-red-200">
                                ML: {classification}
                              </span>
                            )}
                          </div>
                          <span className="text-[10px] text-slate-400 font-mono">
                            {formatTime(event.timestamp)}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 text-[11px]">
                          <span
                            className="font-medium"
                            style={{ color: event.method === 'POST' ? '#f59e0b' : '#06b6d4' }}
                          >
                            {event.method}
                          </span>
                          <span className="text-slate-600 truncate">{event.path}</span>
                          <span
                            className="font-mono font-medium ml-auto shrink-0"
                            style={{
                              color:
                                event.status_code < 300
                                  ? '#10b981'
                                  : event.status_code < 400
                                  ? '#06b6d4'
                                  : event.status_code < 500
                                  ? '#f59e0b'
                                  : '#f43f5e',
                            }}
                          >
                            {event.status_code}
                          </span>
                        </div>
                        {event.indicator && (
                          <p className="text-[10px] text-slate-400 mt-0.5 truncate">
                            {event.indicator}
                          </p>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* MITRE Technique Breakdown (only when connected with data) */}
      {isOnline && labStatus?.mitre_technique_counts && Object.keys(labStatus.mitre_technique_counts).length > 0 && (
        <div className="bg-white rounded-xl border border-slate-200 shadow-xs p-5">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-indigo-500" />
            <h2 className="text-sm font-semibold text-slate-800">MITRE ATT&CK Technique Distribution</h2>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {Object.entries(labStatus.mitre_technique_counts).map(([technique, count]) => {
              const techniqueLabels = {
                T1190: 'SQL Injection / Initial Access',
                'T1059.007': 'XSS / Script Execution',
                T1083: 'File & Directory Discovery',
                T1059: 'Command & Scripting',
                T1110: 'Brute Force',
                T1498: 'Network Denial of Service',
                T1046: 'Network Service Discovery',
              };
              return (
                <div key={technique} className="rounded-lg border border-slate-100 bg-slate-50/50 p-3">
                  <p className="text-xs font-mono font-bold text-indigo-600">{technique}</p>
                  <p className="text-[10px] text-slate-500 mt-0.5 leading-tight">
                    {techniqueLabels[technique] || 'Technique'}
                  </p>
                  <p className="text-lg font-bold text-slate-800 mt-1">{count}</p>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
