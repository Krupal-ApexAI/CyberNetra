import {
  Menu,
  RotateCw,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Flame,
  SlidersHorizontal
} from 'lucide-react';

export default function Navbar({
  activeTab,
  onToggleSidebar,
  scenario,
  onSelectScenario,
  isSwitching,
  isLive,
  onRefresh,
  isRefreshing,
  modelInfo
}) {
  const scenarios = [
    {
      id: 'normal',
      label: 'Normal Traffic',
      tag: 'BASELINE',
      icon: CheckCircle2,
      activeColor: 'bg-emerald-500/15 border-emerald-500/50 text-emerald-300 shadow-sm shadow-emerald-950/40'
    },
    {
      id: 'suspicious',
      label: 'Suspicious Recon',
      tag: 'PROBING',
      icon: Activity,
      activeColor: 'bg-amber-500/15 border-amber-500/50 text-amber-300 shadow-sm shadow-amber-950/40'
    },
    {
      id: 'progression',
      label: 'Attack Progression',
      tag: 'DEMO ?',
      icon: AlertTriangle,
      activeColor: 'bg-orange-500/20 border-orange-500/60 text-orange-300 shadow-sm shadow-orange-950/40 font-semibold'
    },
    {
      id: 'ddos',
      label: 'Volumetric DDoS',
      tag: 'CRITICAL',
      icon: Flame,
      activeColor: 'bg-rose-500/20 border-rose-500/60 text-rose-300 shadow-sm shadow-rose-950/40 font-semibold'
    }
  ];

  const getBreadcrumbTitle = () => {
    switch (activeTab) {
      case 'forecast':
        return 'Attack Stage Forecaster & MITRE Chains';
      case 'explainability':
        return 'Explainable AI (XAI) Attribution Engine';
      case 'traffic':
        return 'Network Telemetry & Flow Ingress';
      case 'alerts':
        return 'SOC Security Incident Queue';
      case 'models':
        return 'Machine Learning Model Registry & Storage';
      default:
        return 'Unified Security Operations Center';
    }
  };

  return (
    <header className="h-16 bg-[#090d16]/95 backdrop-blur-md border-b border-slate-800/80 px-4 sm:px-6 flex items-center justify-between gap-4 sticky top-0 z-20 select-none">
      {/* Left: Toggle & Breadcrumbs */}
      <div className="flex items-center gap-3 min-w-0">
        <button
          onClick={onToggleSidebar}
          className="p-2 rounded-xl bg-slate-900/80 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors focus:outline-none"
          title="Toggle Sidebar"
        >
          <Menu className="w-4 h-4" />
        </button>

        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
            <span>SOC TELEMETRY</span>
            <span>/</span>
            <span className="text-cyan-400 font-semibold uppercase">{activeTab}</span>
          </div>
          <h1 className="text-sm sm:text-base font-bold text-slate-100 truncate tracking-tight">
            {getBreadcrumbTitle()}
          </h1>
        </div>
      </div>

      {/* Center: Real-Time Simulation Injector Pills */}
      <div className="hidden xl:flex items-center bg-[#0b0f19] p-1 rounded-xl border border-slate-800/90 shadow-inner">
        <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider px-2 flex items-center gap-1">
          <SlidersHorizontal className="w-3 h-3 text-cyan-400" />
          Scenario:
        </span>
        <div className="flex items-center gap-1">
          {scenarios.map((sc) => {
            const Icon = sc.icon;
            const isSelected = scenario === sc.id;
            return (
              <button
                key={sc.id}
                onClick={() => onSelectScenario(sc.id)}
                disabled={isSwitching}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs transition-all ${
                  isSelected
                    ? sc.activeColor
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span className="font-medium font-sans">{sc.label}</span>
                <span className="text-[9px] font-mono opacity-80 uppercase px-1 py-0.2 rounded bg-black/20">
                  {sc.tag}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Right: Server Status, Model Info & Refresh */}
      <div className="flex items-center gap-2 sm:gap-3 flex-shrink-0">
        {/* Model Indicator */}
        <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-800 text-[11px] font-mono text-slate-300">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-[0_0_6px_rgba(34,211,238,0.8)]" />
          <span className="text-slate-400">Model:</span>
          <span className="text-cyan-300 font-medium">
            {modelInfo?.name ? 'Custom ML' : 'CyberNetra-Core v1'}
          </span>
        </div>

        {/* Backend Connectivity Status */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-800 text-[11px] font-mono">
          <span
            className={`w-2 h-2 rounded-full ${
              isLive
                ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)] animate-pulse'
                : 'bg-amber-400'
            }`}
          />
          <span className={isLive ? 'text-emerald-300' : 'text-amber-300'}>
            {isLive ? 'FastAPI 8000' : 'Offline Cache'}
          </span>
        </div>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="p-2 rounded-xl bg-slate-900/80 hover:bg-slate-800 text-slate-300 hover:text-cyan-400 border border-slate-800 transition-all focus:outline-none"
          title="Poll fresh telemetry"
        >
          <RotateCw
            className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`}
          />
        </button>
      </div>
    </header>
  );
}
