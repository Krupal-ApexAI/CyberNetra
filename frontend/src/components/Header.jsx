import React from 'react';
import { Shield, Radio, Activity, Cpu, RefreshCw } from 'lucide-react';

export default function Header({ scenario, isLive, onRefresh, isRefreshing, modelInfo }) {
  const scenarioLabels = {
    normal: { text: "Normal Operations", color: "text-emerald-400 border-emerald-500/40 bg-emerald-950/40" },
    suspicious: { text: "Suspicious Reconnaissance", color: "text-amber-400 border-amber-500/40 bg-amber-950/40" },
    progression: { text: "Active Brute-Force Progression", color: "text-orange-400 border-orange-500/40 bg-orange-950/40" },
    ddos: { text: "Critical Volumetric Flood (DDoS)", color: "text-rose-400 border-rose-500/40 bg-rose-950/40" },
  };

  const currentScenarioMeta = scenarioLabels[scenario] || scenarioLabels.normal;

  return (
    <header className="sticky top-0 z-50 w-full border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-xl px-4 sm:px-8 py-3.5 shadow-2xl">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        
        {/* Left: Brand & NTRO Problem Statement Identity */}
        <div className="flex items-center gap-3.5">
          <div className="relative flex items-center justify-center w-11 h-11 rounded-xl bg-gradient-to-br from-cyan-500/20 via-blue-600/20 to-indigo-600/30 border border-cyan-500/40 shadow-lg shadow-cyan-500/10">
            <Shield className="w-6 h-6 text-cyan-400" />
            <div className="absolute -top-1 -right-1 w-3 h-3 bg-cyan-400 rounded-full animate-ping opacity-75" />
            <div className="absolute -top-1 -right-1 w-3 h-3 bg-cyan-400 rounded-full" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xl font-black tracking-wider bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400">
                CYBERNETRA AI
              </span>
              <span className="px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest bg-cyan-950 text-cyan-400 border border-cyan-700/50 rounded">
                SIH26153
              </span>
            </div>
            <p className="text-xs text-slate-400 font-medium">
              AI-Based Predictive Network Attack Forecasting System <span className="text-slate-600 font-mono">| NTRO</span>
            </p>
          </div>
        </div>

        {/* Center/Right: Live Status, Scenario Indicator, Refresh */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Active Scenario Badge */}
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-semibold ${currentScenarioMeta.color}`}>
            <span className="relative flex h-2 w-2">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${scenario === 'ddos' || scenario === 'progression' ? 'bg-rose-400' : 'bg-emerald-400'}`}></span>
              <span className={`relative inline-flex rounded-full h-2 w-2 ${scenario === 'ddos' || scenario === 'progression' ? 'bg-rose-500' : 'bg-emerald-500'}`}></span>
            </span>
            <span className="uppercase text-[11px] tracking-wider text-slate-400">Scenario:</span>
            <span>{currentScenarioMeta.text}</span>
          </div>

          {/* AI Model Indicator */}
          <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900/60 text-xs text-slate-300">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">Model:</span>
            <span className="font-mono text-cyan-300 font-medium text-[11px]">
              {modelInfo?.model_type ? 'Transformer Ensemble' : 'CyberNetra-Core v1'}
            </span>
          </div>

          {/* Backend Connection Health */}
          <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg border border-slate-800/80 bg-slate-900/40 text-xs">
            <Radio className={`w-3.5 h-3.5 ${isLive ? 'text-emerald-400 animate-pulse' : 'text-amber-400'}`} />
            <span className="text-slate-400">{isLive ? 'FastAPI 8000' : 'Offline Cache'}</span>
            <span className={`w-2 h-2 rounded-full ${isLive ? 'bg-emerald-400' : 'bg-amber-400'}`} />
          </div>

          {/* Manual Refresh Button */}
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="p-2 rounded-lg border border-slate-800 bg-slate-900/60 text-slate-400 hover:text-cyan-400 hover:border-cyan-500/50 transition-all cursor-pointer disabled:opacity-50"
            title="Poll fresh telemetry"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>

      </div>
    </header>
  );
}
