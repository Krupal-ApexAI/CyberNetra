import React from 'react';
import { CheckCircle2, Search, Crosshair, Zap, Play } from 'lucide-react';

export default function SimulationControls({ currentScenario, onSelectScenario, isSwitching }) {
  const scenarios = [
    {
      id: 'normal',
      name: 'Normal Traffic',
      tag: 'Baseline',
      desc: 'Standard enterprise traffic with nominal volume',
      icon: CheckCircle2,
      activeColor: 'from-emerald-500/20 via-teal-500/20 to-emerald-900/30 border-emerald-500/70 text-emerald-300 shadow-emerald-500/20',
      badgeColor: 'bg-emerald-950/80 text-emerald-400 border-emerald-500/40',
      iconColor: 'text-emerald-400'
    },
    {
      id: 'suspicious',
      name: 'Suspicious Recon',
      tag: 'Early Signal',
      desc: 'Subnet sweeps & rapid port probe enumeration',
      icon: Search,
      activeColor: 'from-amber-500/20 via-yellow-500/20 to-amber-900/30 border-amber-500/70 text-amber-300 shadow-amber-500/20',
      badgeColor: 'bg-amber-950/80 text-amber-400 border-amber-500/40',
      iconColor: 'text-amber-400'
    },
    {
      id: 'progression',
      name: 'Attack Progression',
      tag: 'Multi-Stage',
      desc: 'Recon -> SSH Brute Force -> Host Breach chain',
      icon: Crosshair,
      activeColor: 'from-orange-500/20 via-rose-500/20 to-red-900/30 border-orange-500/70 text-orange-300 shadow-orange-500/20',
      badgeColor: 'bg-orange-950/80 text-orange-400 border-orange-500/40',
      iconColor: 'text-orange-400'
    },
    {
      id: 'ddos',
      name: 'DDoS Attack',
      tag: 'Critical Surge',
      desc: 'Volumetric SYN flood saturating external gateway',
      icon: Zap,
      activeColor: 'from-rose-500/25 via-red-600/25 to-pink-900/30 border-rose-500/80 text-rose-300 shadow-rose-500/25',
      badgeColor: 'bg-rose-950/80 text-rose-400 border-rose-500/40',
      iconColor: 'text-rose-400'
    }
  ];

  return (
    <div className="w-full glass-panel rounded-2xl p-4 sm:p-5 border border-slate-800/80">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-3.5 mb-3.5 border-b border-slate-800/60 gap-2">
        <div className="flex items-center gap-2">
          <Play className="w-4 h-4 text-cyan-400 fill-cyan-400/30" />
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
            Live Traffic Simulation Engine
          </h2>
          <span className="text-xs text-slate-500 hidden sm:inline">
            — Select a real-time attack vector scenario to test predictive intelligence
          </span>
        </div>
        {isSwitching && (
          <span className="text-xs font-mono text-cyan-400 flex items-center gap-1.5 animate-pulse">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
            Switching scenario stream...
          </span>
        )}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {scenarios.map((sc) => {
          const Icon = sc.icon;
          const isActive = currentScenario === sc.id;

          return (
            <button
              key={sc.id}
              onClick={() => onSelectScenario(sc.id)}
              disabled={isSwitching && isActive}
              className={`group relative flex flex-col items-start p-4 rounded-xl border transition-all duration-200 text-left cursor-pointer ${
                isActive
                  ? `bg-gradient-to-br ${sc.activeColor} shadow-xl ring-1 ring-white/10 scale-[1.01]`
                  : 'bg-slate-900/40 border-slate-800/80 hover:bg-slate-800/50 hover:border-slate-700 text-slate-300'
              }`}
            >
              {/* Header row inside button */}
              <div className="flex items-center justify-between w-full mb-2">
                <div className="flex items-center gap-2">
                  <div className={`p-1.5 rounded-lg ${isActive ? 'bg-black/30' : 'bg-slate-800/60'}`}>
                    <Icon className={`w-4 h-4 ${sc.iconColor}`} />
                  </div>
                  <span className="font-semibold text-sm tracking-wide text-slate-100">
                    {sc.name}
                  </span>
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-medium ${sc.badgeColor}`}>
                  {sc.tag}
                </span>
              </div>

              {/* Description */}
              <p className="text-xs text-slate-400 font-normal leading-relaxed mb-3">
                {sc.desc}
              </p>

              {/* Status indicator badge */}
              <div className="mt-auto w-full pt-2 border-t border-slate-800/40 flex items-center justify-between text-[11px]">
                <span className="text-slate-500 font-mono">Status</span>
                <span className={`font-mono font-medium ${isActive ? 'text-cyan-300' : 'text-slate-500'}`}>
                  {isActive ? '● INJECTING' : '○ Standby'}
                </span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
