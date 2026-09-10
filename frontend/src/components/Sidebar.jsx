import React from 'react';
import {
  LayoutDashboard,
  Activity,
  BrainCircuit,
  FileSearch,
  ShieldAlert,
  Cpu,
  Database,
  ChevronLeft,
  ChevronRight,
  Shield,
  Layers,
  Radio,
  ExternalLink,
  ScrollText
} from 'lucide-react';

export default function Sidebar({
  activeTab,
  onSelectTab,
  isCollapsed,
  onToggleCollapse,
  scenario,
  alertCount = 0
}) {
  const navItems = [
    {
      id: 'all',
      label: 'Operations Center',
      icon: LayoutDashboard,
      badge: 'Unified'
    },
    {
      id: 'forecast',
      label: 'Attack Stage Forecaster',
      icon: BrainCircuit,
      badge: 'MITRE AI'
    },
    {
      id: 'explainability',
      label: 'Explainable AI (XAI)',
      icon: FileSearch,
      badge: 'Dual Trail'
    },
    {
      id: 'traffic',
      label: 'Traffic & Flow Telemetry',
      icon: Activity,
      badge: 'Live Stream'
    },
    {
      id: 'alerts',
      label: 'SOC Incident Queue',
      icon: ShieldAlert,
      badge: alertCount > 0 ? `${alertCount}` : null,
      badgeColor: 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
    },
    {
      id: 'loganalysis',
      label: 'Log Analysis',
      icon: ScrollText,
      badge: 'ML + AI'
    },
    {
      id: 'models',
      label: 'Data & Model Training',
      icon: Database,
      badge: 'ML Engine'
    }
  ];

  return (
    <aside
      className={`relative flex flex-col bg-[#0b0f19] border-r border-slate-800/80 transition-all duration-300 ease-in-out z-30 select-none flex-shrink-0 ${
        isCollapsed ? 'w-[74px]' : 'w-[272px]'
      }`}
    >
      {/* Precision Floating Rail Toggle Button - Always at fixed, reliable coordinates on the boundary line */}
      <button
        type="button"
        onClick={onToggleCollapse}
        className="absolute -right-3.5 top-5 z-50 w-7 h-7 rounded-full bg-[#0b0f19] border border-slate-700 hover:border-cyan-400 text-slate-300 hover:text-cyan-400 shadow-md shadow-black/60 flex items-center justify-center cursor-pointer transition-all hover:scale-110 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
        title={isCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
        aria-label={isCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
      >
        {isCollapsed ? (
          <ChevronRight className="w-4 h-4 stroke-[2.5]" />
        ) : (
          <ChevronLeft className="w-4 h-4 stroke-[2.5]" />
        )}
      </button>

      {/* Brand Header */}
      <div className="h-16 flex items-center px-4 border-b border-slate-800/80 bg-[#090d16] overflow-hidden">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-indigo-600 p-0.5 shadow-lg shadow-cyan-500/20 flex-shrink-0">
            <div className="w-full h-full bg-[#0b0f19] rounded-[10px] flex items-center justify-center">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
          </div>

          {!isCollapsed && (
            <div className="min-w-0 pr-2">
              <div className="flex items-center gap-2">
                <span className="font-extrabold tracking-wider text-base text-slate-100 font-sans whitespace-nowrap">
                  CYBER <span className="text-cyan-400">NETRA</span>
                </span>
                <span className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 whitespace-nowrap">
                  SIH26153
                </span>
              </div>
              <p className="text-[11px] text-slate-400 truncate tracking-tight whitespace-nowrap">
                NTRO Cyber Defense
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Navigation Links */}
      <div className="flex-1 py-4 px-3 space-y-1.5 overflow-y-auto custom-scrollbar">
        {!isCollapsed && (
          <div className="px-3 pb-2 text-[10px] font-mono uppercase tracking-widest text-slate-400">
            Security Intelligence
          </div>
        )}

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;

          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all group relative ${
                isActive
                  ? 'bg-gradient-to-r from-cyan-950/60 to-slate-900/80 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-950/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
              }`}
              title={isCollapsed ? item.label : undefined}
            >
              <Icon
                className={`w-4 h-4 flex-shrink-0 transition-colors ${
                  isActive
                    ? 'text-cyan-400'
                    : 'text-slate-400 group-hover:text-slate-200'
                }`}
              />

              {!isCollapsed && (
                <>
                  <span className="truncate text-left flex-1 font-sans">
                    {item.label}
                  </span>

                  {item.badge && (
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                        item.badgeColor ||
                        (isActive
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                          : 'bg-slate-800/80 text-slate-400')
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </>
              )}

              {/* Active Indicator Bar */}
              {isActive && (
                <div className="absolute left-0 top-1.5 bottom-1.5 w-1 rounded-r-full bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.6)]" />
              )}
            </button>
          );
        })}
      </div>

      {/* Bottom Status Card */}
      <div className="p-3 border-t border-slate-800/80 bg-[#090d16]/80">
        {!isCollapsed ? (
          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-xs text-slate-300 font-medium">
                <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
                <span>Engine State</span>
              </div>
              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-500/30">
                ACTIVE
              </span>
            </div>
            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span>Latency</span>
              <span className="font-mono text-slate-300">~14ms</span>
            </div>
            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span>Telemetry Ingress</span>
              <span className="font-mono text-cyan-400">Kafka / PCAP</span>
            </div>
          </div>
        ) : (
          <div className="flex justify-center py-1" title="Engine Active (~14ms)">
            <div className="w-3 h-3 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
          </div>
        )}
      </div>
    </aside>
  );
}
