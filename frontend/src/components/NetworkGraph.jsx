import React, { useState, useEffect, useRef } from 'react';
import {
  ChevronDown,
  SlidersHorizontal,
  Activity,
  Play,
  Pause,
  Filter,
  Check,
  RotateCcw,
  ArrowRight,
  Radio,
  Wifi,
  ShieldAlert,
  ShieldCheck,
  Server
} from 'lucide-react';
import { fetchNetworkGraph, fetchTraffic } from '../services/api';

export default function NetworkGraph({ scenario = 'normal', onSelectScenario, onNavigateTab, initialMeta }) {
  const [isPlaying, setIsPlaying] = useState(true);
  const [timeframe, setTimeframe] = useState('Last 1 Hour');
  const [showTimeframeMenu, setShowTimeframeMenu] = useState(false);
  const [showFiltersMenu, setShowFiltersMenu] = useState(false);
  
  // Real-time telemetry state
  const [livePackets, setLivePackets] = useState(12438);
  const [liveBandwidth, setLiveBandwidth] = useState('4.8 MB/s');
  const [liveTimestamp, setLiveTimestamp] = useState(new Date().toLocaleTimeString());
  const [backendTopology, setBackendTopology] = useState(null);

  // Interactive Filters
  const [selectedProtocol, setSelectedProtocol] = useState('all'); // 'all', 'tcp', 'udp'
  const [activeLegendFilter, setActiveLegendFilter] = useState(null); // 'source', 'target', null

  // Scenario-specific live telemetry baseline
  const scenarioStats = {
    normal: { basePackets: 240, bandwidth: '0.52 MB/s', attack: 'Baseline Traffic', role: 'Normal Node' },
    suspicious: { basePackets: 1240, bandwidth: '2.80 MB/s', attack: 'Nmap Port Reconnaissance', role: 'Scanner (Suspicious)' },
    progression: { basePackets: 6800, bandwidth: '16.4 MB/s', attack: 'SSH Brute Force / Lateral Spread', role: 'Attacker (Breach)' },
    ddos: { basePackets: 28900, bandwidth: '78.2 MB/s', attack: 'Volumetric DDoS (SYN Flood)', role: 'Attacker (C2 Hub)' }
  };

  const currentStats = scenarioStats[scenario] || scenarioStats.normal;

  const [selectedNode, setSelectedNode] = useState({
    ip: scenario === 'ddos' ? '192.168.1.10' : scenario === 'suspicious' ? '10.0.0.88' : scenario === 'progression' ? '185.220.101.5' : '192.168.1.1',
    role: currentStats.role,
    attackType: currentStats.attack,
    connections: scenario === 'ddos' ? 12 : scenario === 'suspicious' ? 6 : scenario === 'progression' ? 8 : 2,
    firstSeen: '10:23:41',
    lastSeen: new Date().toLocaleTimeString(),
    volume: currentStats.bandwidth
  });

  // Sync selected node when scenario changes
  useEffect(() => {
    const stats = scenarioStats[scenario] || scenarioStats.normal;
    setLivePackets(stats.basePackets);
    setLiveBandwidth(stats.bandwidth);
    setSelectedNode((prev) => ({
      ...prev,
      ip: scenario === 'ddos' ? '192.168.1.10' : scenario === 'suspicious' ? '10.0.0.88' : scenario === 'progression' ? '185.220.101.5' : '192.168.1.1',
      role: stats.role,
      attackType: stats.attack,
      volume: stats.bandwidth,
      connections: scenario === 'ddos' ? 12 : scenario === 'suspicious' ? 6 : scenario === 'progression' ? 8 : 2,
      lastSeen: new Date().toLocaleTimeString()
    }));
  }, [scenario]);

  // Sync selected node when navigating from search or external link
  useEffect(() => {
    if (initialMeta?.ip) {
      const matchSrc = sourceNodes.find(s => s.ip === initialMeta.ip);
      if (matchSrc) {
        setSelectedNode({
          ip: matchSrc.ip,
          role: scenario === 'normal' ? 'Internal Host' : 'Botnet Worker (SYN Flooder)',
          attackType: scenario === 'normal' ? 'Normal Traffic' : 'DDoS Participant',
          connections: 1,
          firstSeen: '10:23:41',
          lastSeen: new Date().toLocaleTimeString(),
          volume: '400 KB/s'
        });
      } else if (initialMeta.ip === '192.168.1.10' || initialMeta.ip === '192.168.1.1') {
        setSelectedNode({
          ip: initialMeta.ip,
          role: scenario === 'normal' ? 'Core Gateway Router' : 'Source (Attacker)',
          attackType: currentStats.attack,
          connections: scenario === 'ddos' ? 12 : 4,
          firstSeen: '10:23:41',
          lastSeen: new Date().toLocaleTimeString(),
          volume: liveBandwidth
        });
      } else if (initialMeta.ip.startsWith('8.8.8.8')) {
        setSelectedNode({
          ip: initialMeta.ip,
          role: 'Destination (Target Server)',
          attackType: scenario === 'normal' ? 'Nominal Service Ingress' : 'Victim Under Attack',
          connections: 12,
          firstSeen: '10:23:41',
          lastSeen: new Date().toLocaleTimeString(),
          volume: liveBandwidth
        });
      }
    }
  }, [initialMeta]);

  // Live Telemetry Polling & Clock Tick
  useEffect(() => {
    if (!isPlaying) return;

    // Fetch live backend topology
    const pollTopology = () => {
      fetchNetworkGraph().then((res) => {
        const data = res?.data || res;
        if (data) setBackendTopology(data);
      });
    };

    pollTopology();

    const interval = setInterval(() => {
      pollTopology();
      const stats = scenarioStats[scenario] || scenarioStats.normal;
      const jitter = Math.floor(Math.random() * (stats.basePackets * 0.15)) - (stats.basePackets * 0.07);
      const newPackets = Math.max(100, Math.round(stats.basePackets + jitter));
      setLivePackets(newPackets);
      setLiveTimestamp(new Date().toLocaleTimeString());

      // Update selected node lastSeen
      setSelectedNode((prev) => ({
        ...prev,
        lastSeen: new Date().toLocaleTimeString()
      }));
    }, 2500);

    return () => clearInterval(interval);
  }, [isPlaying, scenario]);


  const timeframeOptions = ['Last 15 Minutes', 'Last 1 Hour', 'Last 6 Hours', 'Last 24 Hours'];

  // Source IPs on the left arc (Botnet Cluster or Internal Workstations)
  const sourceNodes = [
    { id: 'src-1', ip: '192.168.1.45', x: 230, y: 140 },
    { id: 'src-2', ip: '192.168.1.46', x: 200, y: 170 },
    { id: 'src-3', ip: '192.168.1.47', x: 180, y: 210 },
    { id: 'src-4', ip: '192.168.1.48', x: 170, y: 250 },
    { id: 'src-5', ip: '192.168.1.49', x: 170, y: 290 },
    { id: 'src-6', ip: '192.168.1.50', x: 180, y: 330 },
    { id: 'src-7', ip: '192.168.1.51', x: 200, y: 370 },
    { id: 'src-8', ip: '192.168.1.52', x: 230, y: 400 },
    { id: 'src-9', ip: '192.168.1.53', x: 255, y: 125 },
    { id: 'src-10', ip: '192.168.1.54', x: 285, y: 120 },
    { id: 'src-11', ip: '192.168.1.55', x: 260, y: 415 },
    { id: 'src-12', ip: '192.168.1.56', x: 290, y: 420 }
  ];

  // Target and ports
  const centerNode = { x: 420, y: 270 };
  const targetNode = { x: 620, y: 270 };

  const portNodes = [
    { id: 'p-80', port: 'Port 80', label: 'HTTP', proto: 'tcp', x: 740, y: 170, attack: 'HTTP Flood (8.2k pkts/s)' },
    { id: 'p-443', port: 'Port 443', label: 'HTTPS', proto: 'tcp', x: 750, y: 270, attack: 'SSL Handshake Exhaustion' },
    { id: 'p-53', port: 'Port 53', label: 'DNS', proto: 'udp', x: 740, y: 370, attack: 'Amplified UDP Flood' }
  ];

  const handleViewAllLogs = () => {
    if (onNavigateTab) {
      onNavigateTab('loganalysis', { ip: selectedNode.ip });
    }
  };

  const isDDoS = scenario === 'ddos';
  const isSuspicious = scenario === 'suspicious';
  const isProgression = scenario === 'progression';
  const isNormal = scenario === 'normal';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-900 font-sans tracking-tight">
            Network Graph
          </h2>
          <p className="text-xs text-slate-500 mt-1">
            Real-time live telemetry tracking relationships between IPs, ingress pipes, and attack patterns
          </p>
        </div>

        {/* Controls & Dropdown Actions */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Live Ingress Telemetry Pill */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-xs font-mono shadow-xs">
            <span className={`w-2 h-2 rounded-full ${isPlaying ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'}`} />
            <span className="text-slate-500">Live Ingress:</span>
            <span className="font-bold text-slate-900">{livePackets.toLocaleString()} pkts/s</span>
            <span className="text-slate-400">•</span>
            <span className="text-blue-600 font-semibold">{liveBandwidth}</span>
          </div>

          {/* Pause / Resume Feed Button */}
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-colors cursor-pointer shadow-xs"
          >
            {isPlaying ? <Pause className="w-3.5 h-3.5 text-slate-600" /> : <Play className="w-3.5 h-3.5 text-slate-600" />}
            <span>{isPlaying ? 'Pause Feed' : 'Resume'}</span>
          </button>

          {/* Timeframe Dropdown */}
          <div className="relative">
            <button
              onClick={() => {
                setShowTimeframeMenu(!showTimeframeMenu);
                setShowFiltersMenu(false);
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-colors cursor-pointer shadow-xs"
            >
              <span>{timeframe}</span>
              <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
            </button>

            {showTimeframeMenu && (
              <div className="absolute right-0 mt-2 w-44 bg-white border border-slate-200 rounded-xl shadow-xl p-1.5 z-40 animate-in fade-in duration-100">
                <div className="px-2.5 py-1 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                  Select Timeframe
                </div>
                {timeframeOptions.map((opt) => (
                  <button
                    key={opt}
                    onClick={() => {
                      setTimeframe(opt);
                      setShowTimeframeMenu(false);
                    }}
                    className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs transition-colors cursor-pointer text-left ${
                      timeframe === opt
                        ? 'bg-blue-50 text-blue-700 font-semibold'
                        : 'text-slate-700 hover:bg-slate-50'
                    }`}
                  >
                    <span>{opt}</span>
                    {timeframe === opt && <Check className="w-3.5 h-3.5 text-blue-600" />}
                  </button>
                ))}
              </div>
            )}
          </div>
          
          {/* Filters Dropdown */}
          <div className="relative">
            <button
              onClick={() => {
                setShowFiltersMenu(!showFiltersMenu);
                setShowTimeframeMenu(false);
              }}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors cursor-pointer shadow-xs ${
                selectedProtocol !== 'all' || activeLegendFilter !== null
                  ? 'bg-blue-50 border-blue-200 text-blue-700'
                  : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50'
              }`}
            >
              <SlidersHorizontal className="w-3 h-3 text-slate-500" />
              <span>Filters</span>
              {(selectedProtocol !== 'all' || activeLegendFilter !== null) && (
                <span className="w-2 h-2 rounded-full bg-blue-600" />
              )}
            </button>

            {showFiltersMenu && (
              <div className="absolute right-0 mt-2 w-56 bg-white border border-slate-200 rounded-xl shadow-xl p-3 z-40 animate-in fade-in duration-100 space-y-3">
                <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                  <span className="text-xs font-bold text-slate-900">Topology Filters</span>
                  <button
                    onClick={() => {
                      setSelectedProtocol('all');
                      setActiveLegendFilter(null);
                    }}
                    className="text-[10px] text-blue-600 hover:underline flex items-center gap-1 cursor-pointer"
                  >
                    <RotateCcw className="w-2.5 h-2.5" />
                    <span>Reset</span>
                  </button>
                </div>

                <div>
                  <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block mb-1.5">
                    Protocol Ingress
                  </span>
                  <div className="grid grid-cols-3 gap-1">
                    {['all', 'tcp', 'udp'].map((proto) => (
                      <button
                        key={proto}
                        onClick={() => setSelectedProtocol(proto)}
                        className={`px-2 py-1 rounded-md text-[11px] font-medium uppercase text-center transition-all cursor-pointer ${
                          selectedProtocol === proto
                            ? 'bg-blue-600 text-white font-bold'
                            : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                        }`}
                      >
                        {proto}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block mb-1.5">
                    Filter by Node Type
                  </span>
                  <div className="space-y-1">
                    {[
                      { id: null, label: 'Show All Nodes' },
                      { id: 'source', label: 'Source Ingress IPs Only' },
                      { id: 'target', label: 'Victim Server & Ports Only' }
                    ].map((f) => (
                      <button
                        key={String(f.id)}
                        onClick={() => setActiveLegendFilter(f.id)}
                        className={`w-full text-left px-2 py-1 rounded text-xs transition-colors cursor-pointer flex items-center justify-between ${
                          activeLegendFilter === f.id
                            ? 'bg-blue-50 text-blue-700 font-semibold'
                            : 'text-slate-700 hover:bg-slate-50'
                        }`}
                      >
                        <span>{f.label}</span>
                        {activeLegendFilter === f.id && <Check className="w-3 h-3 text-blue-600" />}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Main Network Graph Visualization Card */}
      <div className="bg-white rounded-xl border border-slate-200/90 p-6 shadow-xs relative">
        {/* Live Status Overlay Header */}
        <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-100">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5 text-xs font-semibold text-slate-700">
              <Radio className="w-3.5 h-3.5 text-emerald-500 animate-pulse" />
              <span>Telemetry Feed:</span>
              <strong className="text-emerald-700 font-mono">LIVE (Port 8000)</strong>
            </span>
            <span className="text-slate-300">•</span>
            <span className="text-xs text-slate-500 font-mono">Synced: {liveTimestamp}</span>
          </div>

          <div className="flex items-center gap-2">
            <span className={`text-[11px] font-mono px-2.5 py-0.5 rounded-full border font-semibold ${
              isDDoS
                ? 'bg-rose-50 text-rose-700 border-rose-200'
                : isSuspicious
                ? 'bg-amber-50 text-amber-700 border-amber-200'
                : isProgression
                ? 'bg-orange-50 text-orange-700 border-orange-200'
                : 'bg-emerald-50 text-emerald-700 border-emerald-200'
            }`}>
              Scenario: {scenario.toUpperCase()}
            </span>
          </div>
        </div>

        <div className="w-full flex justify-center overflow-x-auto">
          <svg viewBox="0 0 900 520" className="w-full max-w-4xl h-auto select-none">
            {/* SVG Defs */}
            <defs>
              <linearGradient id="attackerTargetGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor={isNormal ? '#10b981' : '#ef4444'} />
                <stop offset="100%" stopColor="#3b82f6" />
              </linearGradient>
            </defs>

            {/* 1. Connection lines & Animated Packet Flows from Source IPs to Central Node */}
            {(activeLegendFilter !== 'target') && sourceNodes.map((src, i) => (
              <g key={`src-link-${src.id}`}>
                <line
                  x1={src.x}
                  y1={src.y}
                  x2={centerNode.x}
                  y2={centerNode.y}
                  stroke={isNormal ? '#a7f3d0' : '#fca5a5'}
                  strokeWidth="1.5"
                  strokeDasharray="3 3"
                  opacity={selectedProtocol === 'udp' ? 0.25 : 0.85}
                />

                {/* Animated real-time packet traveling along wire */}
                {isPlaying && selectedProtocol !== 'udp' && (
                  <circle r={isDDoS ? "3" : "2"} fill={isNormal ? '#10b981' : '#ef4444'}>
                    <animateMotion
                      path={`M ${src.x} ${src.y} L ${centerNode.x} ${centerNode.y}`}
                      dur={`${isDDoS ? 0.8 + (i % 4) * 0.15 : 2.0 + (i % 4) * 0.4}s`}
                      repeatCount="indefinite"
                    />
                  </circle>
                )}
              </g>
            ))}

            {/* 2. Main Attack / Communication Trunk: Central Node to Target Node */}
            <g>
              <line
                x1={centerNode.x}
                y1={centerNode.y}
                x2={targetNode.x}
                y2={targetNode.y}
                stroke={isNormal ? '#d1fae5' : '#bfdbfe'}
                strokeWidth={isDDoS ? "10" : "6"}
                opacity="0.5"
              />
              <line
                x1={centerNode.x}
                y1={centerNode.y}
                x2={targetNode.x}
                y2={targetNode.y}
                stroke={isNormal ? '#10b981' : '#3b82f6'}
                strokeWidth={isDDoS ? "5" : "3"}
              />

              {/* High-frequency packet streams surging across the trunk */}
              {isPlaying && (isDDoS ? [0, 0.14, 0.28, 0.42, 0.56, 0.70, 0.84] : [0, 0.6]).map((delay, idx) => (
                <circle key={`trunk-pkt-${idx}`} r={isDDoS ? "4.5" : "3"} fill={isNormal ? '#10b981' : '#ef4444'} stroke="#ffffff" strokeWidth="1">
                  <animateMotion
                    path={`M ${centerNode.x} ${centerNode.y} L ${targetNode.x} ${targetNode.y}`}
                    dur={isDDoS ? "0.85s" : "2.2s"}
                    begin={`${delay}s`}
                    repeatCount="indefinite"
                  />
                </circle>
              ))}
            </g>

            {/* 3. Lines from Target to Port Nodes with Packet Ingress */}
            {(activeLegendFilter !== 'source') && portNodes.map((port, pIdx) => {
              const isDimmed = selectedProtocol === 'tcp' && port.proto !== 'tcp' ||
                               selectedProtocol === 'udp' && port.proto !== 'udp';
              return (
                <g key={`port-link-${port.id}`} opacity={isDimmed ? 0.25 : 1}>
                  <line
                    x1={targetNode.x}
                    y1={targetNode.y}
                    x2={port.x}
                    y2={port.y}
                    stroke={isNormal ? '#93c5fd' : '#f59e0b'}
                    strokeWidth="2"
                    strokeDasharray="4 3"
                  />

                  {isPlaying && !isDimmed && (
                    <circle r="3" fill={isNormal ? '#3b82f6' : '#f59e0b'}>
                      <animateMotion
                        path={`M ${targetNode.x} ${targetNode.y} L ${port.x} ${port.y}`}
                        dur={`${isDDoS ? 0.6 + pIdx * 0.15 : 1.8 + pIdx * 0.3}s`}
                        repeatCount="indefinite"
                      />
                    </circle>
                  )}
                </g>
              );
            })}

            {/* Label for Multiple Sources */}
            {activeLegendFilter !== 'target' && (
              <>
                <text
                  x="210"
                  y="96"
                  textAnchor="middle"
                  className="font-sans font-bold text-xs fill-slate-800"
                >
                  {isNormal ? 'Active Workstations' : 'Multiple Sources'}
                </text>
                <text
                  x="210"
                  y="112"
                  textAnchor="middle"
                  className="font-sans text-[11px] fill-slate-500"
                >
                  (12 IPs)
                </text>
              </>
            )}

            {/* Source Circles (Pink/Salmon or Green for normal) */}
            {activeLegendFilter !== 'target' && sourceNodes.map((src) => {
              const isCurrent = selectedNode.ip === src.ip;
              return (
                <g
                  key={src.id}
                  className="cursor-pointer group"
                  onClick={() =>
                    setSelectedNode({
                      ip: src.ip,
                      role: isNormal ? 'Internal Host' : 'Botnet Worker (SYN Flooder)',
                      attackType: isNormal ? 'Normal Traffic' : 'DDoS Participant',
                      connections: 1,
                      firstSeen: '10:23:41',
                      lastSeen: new Date().toLocaleTimeString(),
                      volume: isNormal ? '45 KB/s' : '400 KB/s'
                    })
                  }
                >
                  {isCurrent && (
                    <circle cx={src.x} cy={src.y} r="12" fill={isNormal ? '#d1fae5' : '#fee2e2'} stroke={isNormal ? '#10b981' : '#ef4444'} strokeWidth="1.5" />
                  )}
                  <circle
                    cx={src.x}
                    cy={src.y}
                    r={isCurrent ? "8" : "6.5"}
                    fill={isNormal ? '#10b981' : '#f87171'}
                    className="hover:scale-125 transition-all"
                  />
                  <title>{src.ip} ({isNormal ? 'Host' : 'Source'})</title>
                </g>
              );
            })}

            {/* Central Attacker / Router Node */}
            <g
              className="cursor-pointer"
              onClick={() =>
                setSelectedNode({
                  ip: isNormal ? '192.168.1.1' : '192.168.1.10',
                  role: isNormal ? 'Core Gateway Router' : 'Source (Attacker)',
                  attackType: currentStats.attack,
                  connections: scenario === 'ddos' ? 12 : 4,
                  firstSeen: '10:23:41',
                  lastSeen: new Date().toLocaleTimeString(),
                  volume: liveBandwidth
                })
              }
            >
              <circle
                cx={centerNode.x}
                cy={centerNode.y}
                r="36"
                fill={isNormal ? '#d1fae5' : '#fee2e2'}
                opacity="0.7"
                className="animate-pulse"
              />
              <circle
                cx={centerNode.x}
                cy={centerNode.y}
                r="26"
                fill={isNormal ? '#059669' : '#ef4444'}
              />
              <circle
                cx={centerNode.x}
                cy={centerNode.y}
                r="10"
                fill="none"
                stroke="#ffffff"
                strokeWidth="3.5"
              />
              <text
                x={centerNode.x}
                y={centerNode.y + 44}
                textAnchor="middle"
                className="font-sans font-bold text-sm fill-slate-900"
              >
                {isNormal ? '192.168.1.1' : '192.168.1.10'}
              </text>
              <text
                x={centerNode.x}
                y={centerNode.y + 60}
                textAnchor="middle"
                className={`font-sans text-xs font-semibold ${isNormal ? 'fill-emerald-600' : 'fill-red-600'}`}
              >
                {isNormal ? '(Gateway)' : isSuspicious ? '(Scanner)' : isProgression ? '(BruteForce)' : '(DDoS)'}
              </text>
            </g>

            {/* Destination Target Node (Blue Hub - 8.8.8.8) */}
            <g
              className="cursor-pointer"
              onClick={() =>
                setSelectedNode({
                  ip: '8.8.8.8',
                  role: 'Destination (Target Server)',
                  attackType: isNormal ? 'Nominal Service Ingress' : 'Victim Under Attack',
                  connections: 12,
                  firstSeen: '10:23:41',
                  lastSeen: new Date().toLocaleTimeString(),
                  volume: liveBandwidth
                })
              }
            >
              <circle
                cx={targetNode.x}
                cy={targetNode.y}
                r="32"
                fill="#dbeafe"
                opacity="0.7"
                className="animate-pulse"
              />
              <circle
                cx={targetNode.x}
                cy={targetNode.y}
                r="24"
                fill="#3b82f6"
              />
              <circle
                cx={targetNode.x}
                cy={targetNode.y}
                r="8"
                fill="#ffffff"
              />
              <text
                x={targetNode.x}
                y={targetNode.y + 42}
                textAnchor="middle"
                className="font-sans font-bold text-sm fill-slate-900"
              >
                8.8.8.8
              </text>
              <text
                x={targetNode.x}
                y={targetNode.y + 58}
                textAnchor="middle"
                className="font-sans text-xs fill-slate-500 font-medium"
              >
                (Target)
              </text>
            </g>

            {/* Port Nodes (Yellow / Blue Service Branch) */}
            {activeLegendFilter !== 'source' && portNodes.map((p) => {
              const isCurrent = selectedNode.ip.includes(p.port.replace('Port ', ''));
              const isDimmed = selectedProtocol === 'tcp' && p.proto !== 'tcp' ||
                               selectedProtocol === 'udp' && p.proto !== 'udp';
              return (
                <g
                  key={p.id}
                  className="cursor-pointer group"
                  opacity={isDimmed ? 0.3 : 1}
                  onClick={() =>
                    setSelectedNode({
                      ip: `8.8.8.8:${p.port.replace('Port ', '')}`,
                      role: `Target Service (${p.label})`,
                      attackType: isNormal ? 'Healthy Port Traffic' : p.attack,
                      connections: isDDoS ? 6 : 2,
                      firstSeen: '10:23:41',
                      lastSeen: new Date().toLocaleTimeString(),
                      volume: isDDoS ? '24.2 MB/s' : '120 KB/s'
                    })
                  }
                >
                  <circle
                    cx={p.x}
                    cy={p.y}
                    r={isCurrent ? "11" : "8"}
                    fill={isNormal ? '#3b82f6' : '#f59e0b'}
                    className="hover:scale-125 transition-all"
                  />
                  <text
                    x={p.x + 15}
                    y={p.y - 1}
                    className="font-sans font-bold text-xs fill-slate-900"
                  >
                    {p.port}
                  </text>
                  <text
                    x={p.x + 15}
                    y={p.y + 13}
                    className="font-sans text-[11px] fill-slate-500"
                  >
                    {p.label}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Legend Row with Interactive Highlighting */}
        <div className="mt-4 pt-4 border-t border-slate-100 flex flex-wrap items-center justify-center gap-6 text-xs font-medium text-slate-600">
          <button
            onClick={() => setActiveLegendFilter(activeLegendFilter === 'source' ? null : 'source')}
            className={`flex items-center gap-2 px-2.5 py-1 rounded-md transition-all cursor-pointer ${
              activeLegendFilter === 'source' ? 'bg-red-50 text-red-700 font-bold' : 'hover:bg-slate-50'
            }`}
          >
            <span className={`w-2.5 h-2.5 rounded-full ${isNormal ? 'bg-emerald-500' : 'bg-red-500'}`} />
            <span>Source IP</span>
          </button>

          <button
            onClick={() => setActiveLegendFilter(activeLegendFilter === 'target' ? null : 'target')}
            className={`flex items-center gap-2 px-2.5 py-1 rounded-md transition-all cursor-pointer ${
              activeLegendFilter === 'target' ? 'bg-blue-50 text-blue-700 font-bold' : 'hover:bg-slate-50'
            }`}
          >
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500" />
            <span>Destination IP</span>
          </button>

          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-pink-300" />
            <span>Related IP</span>
          </div>

          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
            <span>Suspicious</span>
          </div>

          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
            <span>Normal</span>
          </div>
        </div>
      </div>

      {/* Selected Node Information Card Matching Mockup 5 */}
      <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-4">
          <div className="flex items-center gap-2.5">
            <Activity className="w-4 h-4 text-blue-600" />
            <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight">
              Selected Node Information
            </h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 font-semibold">
              Live Ingress Inspector
            </span>
          </div>

          {/* Active "View All Logs →" button navigating to log analysis */}
          <button
            onClick={handleViewAllLogs}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold transition-colors cursor-pointer shadow-xs"
          >
            <span>View All Logs ({selectedNode.ip})</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-6 gap-4 text-xs font-sans">
          <div>
            <span className="text-slate-500 font-medium block">IP Address</span>
            <span className="font-bold text-slate-900 mt-1 block font-mono">
              {selectedNode.ip}
            </span>
          </div>
          <div>
            <span className="text-slate-500 font-medium block">Role</span>
            <span className="font-semibold text-slate-800 mt-1 block">
              {selectedNode.role}
            </span>
          </div>
          <div>
            <span className="text-slate-500 font-medium block">Attack Type</span>
            <span className={`font-bold mt-1 block ${isNormal ? 'text-emerald-600' : 'text-red-600'}`}>
              {selectedNode.attackType}
            </span>
          </div>
          <div>
            <span className="text-slate-500 font-medium block">Total Connections</span>
            <span className="font-bold text-slate-900 mt-1 block font-mono">
              {selectedNode.connections}
            </span>
          </div>
          <div>
            <span className="text-slate-500 font-medium block">First Seen</span>
            <span className="text-slate-700 mt-1 block font-mono">
              {selectedNode.firstSeen}
            </span>
          </div>
          <div>
            <span className="text-slate-500 font-medium block">Last Seen</span>
            <span className="text-blue-600 mt-1 block font-mono font-semibold">
              {selectedNode.lastSeen}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
