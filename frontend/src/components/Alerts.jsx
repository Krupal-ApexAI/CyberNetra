import React, { useState } from 'react';
import { Bell, AlertOctagon, AlertTriangle, Info, ShieldAlert, Filter } from 'lucide-react';

export default function Alerts({ alerts = [] }) {
  const [filter, setFilter] = useState('ALL');

  const filteredAlerts = alerts.filter((alert) => {
    if (filter === 'ALL') return true;
    return alert.severity === filter;
  });

  const getAlertStyle = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return {
          border: 'border-rose-600/40 bg-rose-950/20',
          badge: 'bg-rose-950 text-rose-400 border-rose-600/60',
          icon: AlertOctagon,
          iconColor: 'text-rose-400'
        };
      case 'HIGH':
        return {
          border: 'border-orange-600/40 bg-orange-950/20',
          badge: 'bg-orange-950 text-orange-400 border-orange-600/60',
          icon: ShieldAlert,
          iconColor: 'text-orange-400'
        };
      case 'MEDIUM':
        return {
          border: 'border-amber-600/40 bg-amber-950/20',
          badge: 'bg-amber-950 text-amber-400 border-amber-600/60',
          icon: AlertTriangle,
          iconColor: 'text-amber-400'
        };
      default:
        return {
          border: 'border-emerald-600/40 bg-emerald-950/20',
          badge: 'bg-emerald-950 text-emerald-400 border-emerald-600/60',
          icon: Info,
          iconColor: 'text-emerald-400'
        };
    }
  };

  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH').length;

  return (
    <div className="w-full glass-panel rounded-2xl p-5 border border-slate-800/80 flex flex-col justify-between">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-3.5 mb-3 border-b border-slate-800/60 gap-2">
        <div className="flex items-center gap-2.5">
          <div className="relative p-1.5 rounded-lg bg-rose-500/10 border border-rose-500/30">
            <Bell className="w-4 h-4 text-rose-400" />
            {criticalCount > 0 && (
              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-rose-500 rounded-full animate-ping" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold tracking-wide text-slate-200">
                Security Operations Center (SOC) Alerts
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                {alerts.length} Total
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Live chronological security event stream
            </p>
          </div>
        </div>

        {/* Severity Filter Tabs */}
        <div className="flex items-center gap-1 bg-slate-900/80 border border-slate-800 p-1 rounded-lg text-xs font-mono">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
            <button
              key={lvl}
              onClick={() => setFilter(lvl)}
              className={`px-2 py-0.5 rounded transition-all cursor-pointer ${
                filter === lvl
                  ? 'bg-slate-700 text-white font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      {/* Alert Feed List */}
      <div className="space-y-2.5 max-h-80 overflow-y-auto pr-1">
        {filteredAlerts.length > 0 ? (
          filteredAlerts.map((alert) => {
            const style = getAlertStyle(alert.severity);
            const Icon = style.icon;

            return (
              <div
                key={alert.id}
                className={`p-3 rounded-xl border ${style.border} transition-all hover:bg-slate-900/60 flex flex-col gap-1.5`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Icon className={`w-4 h-4 ${style.iconColor} shrink-0`} />
                    <span className="text-xs font-bold text-slate-100">
                      {alert.title}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    {alert.mitre_id && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 border border-indigo-700/50 font-semibold">
                        {alert.mitre_id}
                      </span>
                    )}
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${style.badge}`}>
                      {alert.severity}
                    </span>
                  </div>
                </div>

                <p className="text-xs text-slate-300 leading-snug pl-6">
                  {alert.message}
                </p>

                <div className="flex items-center justify-between pl-6 text-[10px] font-mono text-slate-500 pt-1 border-t border-slate-800/40">
                  <span>ID: {alert.id}</span>
                  <span>Logged: {alert.timestamp} UTC</span>
                </div>
              </div>
            );
          })
        ) : (
          <div className="py-8 text-center text-xs font-mono text-slate-500">
            No alerts matching filter criteria '{filter}'.
          </div>
        )}
      </div>

      {/* Footer Info */}
      <div className="pt-3 mt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] font-mono text-slate-500">
        <span>Continuous SIEM Ingestion</span>
        <span className="text-emerald-400 flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          Active Pipeline
        </span>
      </div>
    </div>
  );
}
