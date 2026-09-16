import React from 'react';
import {
  LayoutDashboard,
  Activity,
  ScrollText,
  ShieldAlert,
  Clock,
  Share2,
  BrainCircuit,
  Layers,
  Cpu,
  FileText,
  Shield,
  FlaskConical,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';

export default function Sidebar({
  activeTab,
  onSelectTab,
  isCollapsed,
  onToggleCollapse
}) {
  const navItems = [
    { id: 'all', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'live', label: 'Live Monitoring', icon: Activity },
    { id: 'loganalysis', label: 'Log Analysis', icon: ScrollText },
    { id: 'threats', label: 'Threats', icon: ShieldAlert },
    { id: 'timeline', label: 'Attack Timeline', icon: Clock },
    { id: 'graph', label: 'Network Graph', icon: Share2 },
    { id: 'explainability', label: 'AI Explanations', icon: BrainCircuit },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: Layers },
    { id: 'models', label: 'Model Performance', icon: Cpu },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'lab', label: 'Vulnerable Lab', icon: FlaskConical }
  ];

  return (
    <aside
      className={`relative flex flex-col bg-[#0b1322] text-slate-300 border-r border-[#182338] transition-all duration-300 ease-in-out z-30 select-none shrink-0 ${
        isCollapsed ? 'w-[72px]' : 'w-[240px]'
      }`}
    >
      {/* Collapse Toggle Button - Translucent Glassmorphic Boundary Pill */}
      <button
        type="button"
        onClick={onToggleCollapse}
        className="absolute -right-3.5 top-20 z-50 w-7 h-7 rounded-full bg-slate-900/80 backdrop-blur-md border border-slate-500/60 hover:border-blue-400 text-slate-200 hover:text-white hover:bg-blue-600/90 shadow-md shadow-black/40 flex items-center justify-center cursor-pointer transition-all duration-200 hover:scale-110 active:scale-95 group"
        title={isCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
        aria-label="Toggle Sidebar"
      >
        {isCollapsed ? (
          <ChevronRight className="w-3.5 h-3.5 text-blue-400 group-hover:text-white transition-transform group-hover:translate-x-0.5" />
        ) : (
          <ChevronLeft className="w-3.5 h-3.5 text-slate-300 group-hover:text-white transition-transform group-hover:-translate-x-0.5" />
        )}
      </button>

      {/* Brand Header Matching Mockup 2 - Clickable to return to Home Landing Page */}
      <div
        onClick={() => onSelectTab('home')}
        className="h-16 flex items-center px-4 border-b border-[#182338] shrink-0 cursor-pointer hover:bg-[#101b2e] transition-colors group"
        title="Return to Home / Landing Page"
      >
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-blue-600 group-hover:bg-blue-500 flex items-center justify-center shrink-0 shadow-sm shadow-blue-500/40 transition-colors">
            <Shield className="w-4 h-4 text-white" />
          </div>

          {!isCollapsed && (
            <div className="min-w-0">
              <h1 className="font-bold text-sm text-white tracking-tight leading-tight group-hover:text-blue-200 transition-colors">
                CyberNetra
              </h1>
              <p className="text-[10px] text-slate-400 truncate leading-tight mt-0.5">
                Network Threat Intelligence
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Navigation Menu List */}
      <div className="flex-1 py-4 px-2.5 space-y-1 overflow-y-auto custom-scrollbar">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;

          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`flex items-center gap-3 w-full px-3 py-2 rounded-lg text-xs font-medium transition-all text-left cursor-pointer ${
                isActive
                  ? 'bg-blue-600 text-white font-semibold shadow-xs'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-white/5'
              }`}
              title={isCollapsed ? item.label : undefined}
            >
              <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-white' : 'text-slate-400'}`} />
              {!isCollapsed && (
                <span className="truncate">{item.label}</span>
              )}
            </button>
          );
        })}
      </div>

      {/* Bottom Slogan Footer Matching Mockup 2 */}
      {!isCollapsed && (
        <div className="p-4 border-t border-[#182338] shrink-0">
          <p className="text-[11px] font-semibold text-slate-300 leading-snug">
            Safer Networks<br />Stronger Tomorrow
          </p>
          <p className="text-[9px] text-slate-500 leading-snug mt-1">
            A Smart India Hackathon 2026 Initiative
          </p>
        </div>
      )}
    </aside>
  );
}
