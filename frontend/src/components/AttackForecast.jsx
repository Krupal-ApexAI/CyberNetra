import { BrainCircuit, Target, AlertOctagon, Layers } from 'lucide-react';

export default function AttackForecast({ forecast, scenario = 'normal' }) {
  const {
    current_state = "Baseline Telemetry",
    current_tactic = "Normal Operations",
    predicted_next_attack = "None Anticipated",
    predicted_tactic = "None",
    potential_impact = "Nominal operational state. All security controls verified.",
    confidence = 96,
    model_used = "CYBERNETRA Neural Ensemble v1.0",
    summary = "Telemetry parameters indicate benign normal user activity across all enterprise segments."
  } = forecast || {};

  const isThreat = scenario !== 'normal';

  return (
    <div className="w-full glass-panel rounded-2xl p-5 border border-slate-800/80">
      {/* Panel Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-3.5 mb-4 border-b border-slate-800/60 gap-2">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-indigo-500/10 border border-indigo-500/30">
            <BrainCircuit className="w-4 h-4 text-indigo-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold tracking-wide text-slate-200">
              Predictive Attack Stage Forecasting (MITRE ATT&CK Chain)
            </h3>
            <p className="text-xs text-slate-400">
              AI sequence forecasting projected from current live traffic vectors
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-indigo-950/70 border border-indigo-500/40 text-indigo-300">
            {model_used}
          </span>
        </div>
      </div>

      {/* 3-Stage Attack Progression Chain */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 my-2 relative">
        
        {/* Stage 1: Observed Attack Stage */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800 flex flex-col justify-between relative overflow-hidden group">
          <div className="absolute top-0 left-0 w-1 h-full bg-cyan-500" />
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase font-mono tracking-wider text-cyan-400 font-semibold flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                Step 1: Observed State
              </span>
              <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                DETECTED
              </span>
            </div>
            <h4 className="text-base font-bold text-slate-100 mb-1.5">
              {current_state}
            </h4>
            <div className="inline-block px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-700/50 text-xs font-mono mb-2">
              {current_tactic}
            </div>
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Identified via deep packet payload & telemetry signature analysis.
          </p>
        </div>

        {/* Stage 2: Predicted Next Attack */}
        <div className={`glass-panel p-4 rounded-xl border flex flex-col justify-between relative overflow-hidden group ${
          isThreat ? 'border-amber-500/50 bg-amber-950/10' : 'border-slate-800'
        }`}>
          <div className={`absolute top-0 left-0 w-1 h-full ${isThreat ? 'bg-amber-400' : 'bg-slate-700'}`} />
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase font-mono tracking-wider text-amber-400 font-semibold flex items-center gap-1.5">
                <Target className="w-3 h-3 text-amber-400" />
                Step 2: AI Projected Next
              </span>
              <span className="text-[10px] font-mono text-amber-300 bg-amber-950/80 px-2 py-0.5 rounded border border-amber-600/50 font-bold">
                {confidence}% PROBABILITY
              </span>
            </div>
            <h4 className="text-base font-bold text-slate-100 mb-1.5">
              {predicted_next_attack}
            </h4>
            <div className="inline-block px-2 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-700/50 text-xs font-mono mb-2">
              {predicted_tactic}
            </div>
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Transformer sequence inference predicts transition prior to execution.
          </p>
        </div>

        {/* Stage 3: Potential Impact */}
        <div className={`glass-panel p-4 rounded-xl border flex flex-col justify-between relative overflow-hidden group ${
          isThreat ? 'border-rose-500/40 bg-rose-950/10' : 'border-slate-800'
        }`}>
          <div className={`absolute top-0 left-0 w-1 h-full ${isThreat ? 'bg-rose-500' : 'bg-slate-700'}`} />
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase font-mono tracking-wider text-rose-400 font-semibold flex items-center gap-1.5">
                <AlertOctagon className="w-3 h-3 text-rose-400" />
                Step 3: Potential Impact
              </span>
              <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                CONSEQUENCE
              </span>
            </div>
            <h4 className="text-base font-bold text-slate-100 mb-1.5">
              {isThreat ? 'Targeted Asset Compromise' : 'Nominal Infrastructure'}
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed">
              {potential_impact}
            </p>
          </div>
          <div className="mt-3 pt-2 border-t border-slate-800/60 text-[11px] font-mono text-slate-500">
            Mitigation required before transition completion.
          </div>
        </div>

      </div>

      {/* Summary Narrative Banner */}
      <div className="mt-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex items-start gap-2.5">
        <Layers className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 leading-relaxed">
          <span className="font-semibold text-slate-200">Intelligence Brief: </span>
          {summary}
        </div>
      </div>
    </div>
  );
}
