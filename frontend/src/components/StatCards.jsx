import React from 'react';
import { Activity, Server, AlertTriangle, ShieldCheck, ShieldAlert, Wifi } from 'lucide-react';

export default function StatCards({ stats, scenario }) {
  const {
    network_status = "Healthy",
    active_devices = 38,
    suspicious_traffic_percent = 0.0,
    active_threat = "None - Baseline Traffic",
    risk_level = "LOW"
  } = stats || {};

  const getStatusTheme = () => {
    switch (scenario) {
      case 'ddos':
        return {
          border: 'border-rose-500/40',
          bg: 'from-rose-950/20 to-slate-900/40',
          text: 'text-rose-400',
          icon: ShieldAlert
        };
      case 'progression':
        return {
          border: 'border-orange-500/40',
          bg: 'from-orange-950/20 to-slate-900/40',
          text: 'text-orange-400',
          icon: AlertTriangle
        };
      case 'suspicious':
        return {
          border: 'border-amber-500/40',
          bg: 'from-amber-950/20 to-slate-900/40',
          text: 'text-amber-400',
          icon: Activity
        };
      default:
        return {
          border: 'border-emerald-500/40',
          bg: 'from-emerald-950/20 to-slate-900/40',
          text: 'text-emerald-400',
          icon: ShieldCheck
        };
    }
  };

  const statusTheme = getStatusTheme();
  const StatusIcon = statusTheme.icon;

  const cards = [
    {
      title: 'Network Posture',
      value: network_status,
      icon: StatusIcon,
      subtitle: `Threat Level: ${risk_level}`,
      accent: statusTheme.text,
      borderGlow: statusTheme.border,
      gradient: statusTheme.bg,
      badge: scenario.toUpperCase()
    },
    {
      title: 'Active Endpoints',
      value: active_devices,
      icon: Server,
      subtitle: 'Internal subnets & gateways',
      accent: 'text-cyan-400',
      borderGlow: 'border-cyan-500/30',
      gradient: 'from-cyan-950/20 to-slate-900/40',
      badge: 'MONITORED'
    },
    {
      title: 'Suspicious Traffic Ratio',
      value: `${suspicious_traffic_percent.toFixed(1)}%`,
      icon: Activity,
      subtitle: suspicious_traffic_percent > 50 ? 'Severe anomaly threshold' : suspicious_traffic_percent > 10 ? 'Elevated anomaly rate' : 'Baseline normal deviation',
      accent: suspicious_traffic_percent > 50 ? 'text-rose-400' : suspicious_traffic_percent > 10 ? 'text-amber-400' : 'text-emerald-400',
      borderGlow: suspicious_traffic_percent > 50 ? 'border-rose-500/30' : suspicious_traffic_percent > 10 ? 'border-amber-500/30' : 'border-emerald-500/30',
      gradient: suspicious_traffic_percent > 50 ? 'from-rose-950/20 to-slate-900/40' : 'from-slate-900/40 to-slate-900/40',
      badge: 'REAL-TIME'
    },
    {
      title: 'Active Threat Vector',
      value: active_threat,
      icon: Wifi,
      subtitle: 'Derived by heuristic & model classification',
      accent: scenario === 'normal' ? 'text-emerald-400' : 'text-sky-300',
      borderGlow: 'border-slate-800 hover:border-slate-700',
      gradient: 'from-blue-950/20 to-slate-900/40',
      badge: 'AI CLASSIFIED'
    }
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`glass-panel rounded-2xl p-4.5 border transition-all duration-300 bg-gradient-to-br ${card.gradient} ${card.borderGlow} hover:scale-[1.01]`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                {card.title}
              </span>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700/60">
                  {card.badge}
                </span>
                <div className="p-1.5 rounded-lg bg-slate-800/50">
                  <Icon className={`w-4 h-4 ${card.accent}`} />
                </div>
              </div>
            </div>

            <div className="my-1">
              <div className={`text-xl sm:text-2xl font-bold tracking-tight truncate ${card.accent}`}>
                {card.value}
              </div>
            </div>

            <p className="text-xs text-slate-500 mt-2 font-medium truncate">
              {card.subtitle}
            </p>
          </div>
        );
      })}
    </div>
  );
}
