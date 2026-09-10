import React, { useState } from 'react';
import {
  FileText,
  Clock,
  ShieldAlert,
  ArrowRight,
  ShieldCheck,
  CheckCircle,
  AlertTriangle,
  Server,
  Terminal,
  Copy,
  Check
} from 'lucide-react';

export default function ExplainabilityPanel({ data }) {
  const {
    current_threat = "Normal Traffic Baseline",
    what_happened_summary = "Observed telemetry parameters reflect standard operations.",
    evidence_trail = [],
    whats_next_prediction = "Steady-State Continuance",
    whats_next_details = "Predictive model projects network traffic will remain within safe baseline.",
    attack_trajectory = [],
    target_assets = [],
    estimated_time_to_impact = "None",
    mitigation_playbook = []
  } = data || {};

  const [copiedIdx, setCopiedIdx] = useState(null);

  const handleCopyPlaybook = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 1800);
  };

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-950 text-rose-400 border-rose-500/50';
      case 'HIGH':
        return 'bg-orange-950 text-orange-400 border-orange-500/50';
      case 'MEDIUM':
        return 'bg-amber-950 text-amber-400 border-amber-500/50';
      default:
        return 'bg-emerald-950 text-emerald-400 border-emerald-500/50';
    }
  };

  return (
    <div className="w-full glass-panel rounded-2xl p-5 border border-slate-800/80">
      {/* Panel Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-3.5 mb-4 border-b border-slate-800/60 gap-2">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
            <Terminal className="w-4 h-4 text-cyan-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold tracking-wide text-slate-200">
              Explainable AI (XAI) & Incident Attribution Engine
            </h3>
            <p className="text-xs text-slate-400">
              Dual forensic trail: Retrospective telemetry evidence vs. Proactive attack path forecast
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <Clock className="w-3.5 h-3.5 text-slate-500" />
          <span>ETA to Critical Impact: </span>
          <span className="text-rose-400 font-bold px-2 py-0.5 rounded bg-rose-950/70 border border-rose-600/40">
            {estimated_time_to_impact}
          </span>
        </div>
      </div>

      {/* Split View: Retrospective (What Happened) VS Prospective (What's Going to Happen) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        
        {/* Left Column: WHAT HAPPENED UNTIL NOW */}
        <div className="flex flex-col space-y-3.5 p-4 rounded-xl bg-slate-900/40 border border-slate-800/80">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
              <h4 className="text-sm font-bold text-slate-200 uppercase tracking-wide">
                1. What Happened Until Now
              </h4>
            </div>
            <span className="text-[11px] font-mono text-cyan-300 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/60">
              Retrospective Evidence
            </span>
          </div>

          {/* Narrative Summary */}
          <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/50 p-3 rounded-lg border border-slate-800/60">
            {what_happened_summary}
          </p>

          {/* Evidence Trail List */}
          <div>
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-2 font-semibold">
              Telemetry Evidence Trail
            </span>
            <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
              {evidence_trail && evidence_trail.length > 0 ? (
                evidence_trail.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/70 hover:border-slate-700 text-xs transition-colors"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-semibold text-slate-200">{item.indicator}</span>
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border uppercase font-bold ${getSeverityBadge(item.severity)}`}>
                        {item.severity}
                      </span>
                    </div>

                    <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400 mb-1">
                      <div>
                        Observed: <span className="text-cyan-300 font-bold">{item.observed_value}</span>
                      </div>
                      <div>
                        Baseline: <span className="text-slate-500">{item.baseline_value}</span>
                      </div>
                    </div>

                    <p className="text-[11px] text-slate-400 leading-snug">
                      {item.description}
                    </p>
                  </div>
                ))
              ) : (
                <div className="text-xs text-slate-500 font-mono text-center py-4">
                  No anomalous evidence triggers logged.
                </div>
              )}
            </div>
          </div>

          {/* Target Assets Impacted */}
          {target_assets && target_assets.length > 0 && (
            <div className="pt-2 border-t border-slate-800/80">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-1.5 font-semibold">
                Target Assets / Subnets
              </span>
              <div className="flex flex-wrap gap-1.5">
                {target_assets.map((asset, idx) => (
                  <span
                    key={idx}
                    className="flex items-center gap-1 text-[11px] font-mono px-2 py-1 rounded bg-slate-800/80 text-slate-300 border border-slate-700/60"
                  >
                    <Server className="w-3 h-3 text-cyan-400" />
                    {asset}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: WHAT'S GOING TO HAPPEN NEXT & DEFENSE PLAYBOOK */}
        <div className="flex flex-col space-y-3.5 p-4 rounded-xl bg-slate-900/40 border border-slate-800/80">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-indigo-400" />
              <h4 className="text-sm font-bold text-slate-200 uppercase tracking-wide">
                2. What's Going to Happen Next
              </h4>
            </div>
            <span className="text-[11px] font-mono text-indigo-300 bg-indigo-950/60 px-2 py-0.5 rounded border border-indigo-800/60">
              Predictive Trajectory
            </span>
          </div>

          {/* Prediction summary */}
          <div className="bg-slate-950/50 p-3 rounded-lg border border-slate-800/60">
            <div className="text-xs font-bold text-indigo-300 mb-1">
              Projected Attack Phase: {whats_next_prediction}
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {whats_next_details}
            </p>
          </div>

          {/* Projected Trajectory Path */}
          {attack_trajectory && attack_trajectory.length > 0 && (
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-2 font-semibold">
                Projected Attack Progression Trajectory
              </span>
              <div className="flex flex-wrap items-center gap-1.5 p-2 rounded-lg bg-slate-950/50 border border-slate-800 text-xs">
                {attack_trajectory.map((step, idx) => (
                  <React.Fragment key={idx}>
                    <span className={`px-2 py-1 rounded font-mono font-medium ${
                      idx === attack_trajectory.length - 1
                        ? 'bg-rose-950/70 text-rose-300 border border-rose-800/60'
                        : 'bg-slate-800 text-slate-300'
                    }`}>
                      {step}
                    </span>
                    {idx < attack_trajectory.length - 1 && (
                      <ArrowRight className="w-3 h-3 text-slate-600" />
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>
          )}

          {/* Defensive Mitigation Playbook */}
          <div className="flex-1 flex flex-col justify-between">
            <span className="text-xs font-mono text-emerald-400 uppercase tracking-wider block mb-2 font-semibold flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              Automated Defensive Mitigation Playbook
            </span>

            <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
              {mitigation_playbook && mitigation_playbook.length > 0 ? (
                mitigation_playbook.map((action, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between p-2 rounded-lg bg-slate-950/80 border border-emerald-900/30 text-xs text-slate-200 group hover:border-emerald-700/50 transition-colors"
                  >
                    <div className="flex items-start gap-2 pr-2">
                      <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                      <span className="font-mono text-[11px] leading-tight text-slate-300">
                        {action}
                      </span>
                    </div>

                    <button
                      onClick={() => handleCopyPlaybook(action, idx)}
                      className="p-1 rounded text-slate-500 hover:text-cyan-400 hover:bg-slate-800 transition-colors cursor-pointer shrink-0"
                      title="Copy action command"
                    >
                      {copiedIdx === idx ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  </div>
                ))
              ) : (
                <div className="text-xs text-slate-500 font-mono text-center py-4">
                  Standard baseline monitoring rules applied.
                </div>
              )}
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}
