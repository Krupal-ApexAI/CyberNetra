import React, { useState, useMemo } from 'react';
import {
  ScrollText, Play, Trash2, FileDown, ShieldCheck, ShieldAlert,
  AlertTriangle, ChevronDown, ChevronUp, Brain, Cpu, Zap,
  Target, Info, Loader2, ArrowRight, Clock
} from 'lucide-react';
import { analyzeLogsAPI } from '../services/api';

// ─── Sample log data for demo ───
const SAMPLE_LOGS = `2026-09-11 00:42:16 TCP 192.168.1.45:49231 -> 10.0.0.20:80
2026-09-11 00:42:16 TCP 192.168.1.45:49232 -> 10.0.0.20:80
2026-09-11 00:42:17 TCP 192.168.1.45:49233 -> 10.0.0.20:80
2026-09-11 00:42:17 TCP 192.168.1.45:49234 -> 10.0.0.20:80
2026-09-11 00:42:17 TCP 192.168.1.45:49235 -> 10.0.0.20:80
2026-09-11 00:42:18 TCP 192.168.1.45:49236 -> 10.0.0.20:80
2026-09-11 00:42:18 TCP 192.168.1.45:49237 -> 10.0.0.20:80
2026-09-11 00:42:18 TCP 192.168.1.45:49238 -> 10.0.0.20:443
2026-09-11 00:42:19 TCP 192.168.1.45:49239 -> 10.0.0.20:443
2026-09-11 00:42:19 TCP 192.168.1.45:49240 -> 10.0.0.20:443
2026-09-11 00:42:19 TCP 192.168.1.45:49241 -> 10.0.0.20:22
2026-09-11 00:42:20 TCP 192.168.1.45:49242 -> 10.0.0.20:22
2026-09-11 00:42:20 TCP 192.168.1.45:49243 -> 10.0.0.20:3389
2026-09-11 00:42:20 UDP 192.168.1.45:49244 -> 10.0.0.20:53
2026-09-11 00:42:21 TCP 192.168.1.45:49245 -> 10.0.0.20:445
2026-09-11 00:42:21 TCP 192.168.1.45:49246 -> 10.0.0.20:8080
2026-09-11 00:42:21 TCP 192.168.1.45:49247 -> 10.0.0.20:21
2026-09-11 00:42:22 TCP 192.168.1.45:49248 -> 10.0.0.20:23
2026-09-11 00:42:22 TCP 192.168.1.45:49249 -> 10.0.0.20:25
2026-09-11 00:42:22 TCP 192.168.1.45:49250 -> 10.0.0.20:3306`;

// ─── Risk level styling ───
const RISK_STYLES = {
  CRITICAL: { bg: 'from-rose-950/40 to-rose-900/20', border: 'border-rose-500/50', text: 'text-rose-400', badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40' },
  HIGH:     { bg: 'from-orange-950/40 to-orange-900/20', border: 'border-orange-500/50', text: 'text-orange-400', badge: 'bg-orange-500/20 text-orange-300 border-orange-500/40' },
  MEDIUM:   { bg: 'from-amber-950/40 to-amber-900/20', border: 'border-amber-500/50', text: 'text-amber-400', badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40' },
  LOW:      { bg: 'from-emerald-950/40 to-emerald-900/20', border: 'border-emerald-500/50', text: 'text-emerald-400', badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' },
};

const getRiskStyle = (level) => RISK_STYLES[level] || RISK_STYLES.MEDIUM;

export default function LogAnalysis() {
  const [logs, setLogs] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [showTimeline, setShowTimeline] = useState(false);

  // Derived stats
  const lineCount = useMemo(() => logs.trim() ? logs.trim().split('\n').length : 0, [logs]);
  const charCount = logs.length;

  const handleAnalyze = async () => {
    if (!logs.trim()) return;
    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      const data = await analyzeLogsAPI(logs);
      setResult(data);
    } catch (err) {
      setError(err.message || 'Analysis failed. Please check the backend connection.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleClear = () => {
    setLogs('');
    setResult(null);
    setError(null);
  };

  const handleLoadSample = () => {
    setLogs(SAMPLE_LOGS);
    setResult(null);
    setError(null);
  };

  const isAttack = result && result.attack_events > 0;
  const riskLevel = result?.incident?.risk_level || 'LOW';
  const riskStyle = getRiskStyle(riskLevel);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2.5 rounded-xl bg-gradient-to-br from-violet-600/20 to-cyan-600/20 border border-violet-500/30">
          <ScrollText className="w-5 h-5 text-violet-400" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-slate-100 tracking-tight">Log Analysis</h2>
          <p className="text-xs text-slate-400">ML-powered intrusion detection with AI-generated security explanations</p>
        </div>
      </div>

      {/* Input Section */}
      <div className="glass-panel rounded-2xl p-5 border border-slate-800/80">
        <div className="flex items-center justify-between mb-3">
          <label className="text-sm font-semibold text-slate-300 flex items-center gap-2">
            <ScrollText className="w-4 h-4 text-cyan-400" />
            Network Log Input
          </label>
          <div className="flex items-center gap-3 text-xs text-slate-500 font-mono">
            <span>{lineCount} lines</span>
            <span>•</span>
            <span>{charCount.toLocaleString()} chars</span>
          </div>
        </div>

        <textarea
          id="log-input-textarea"
          value={logs}
          onChange={(e) => setLogs(e.target.value)}
          placeholder={`Paste network logs here...\n\n2026-09-11 00:42:16 TCP 192.168.1.45:49231 -> 10.0.0.20:80\n2026-09-11 00:42:17 TCP 192.168.1.45:49232 -> 10.0.0.20:80\n2026-09-11 00:42:17 TCP 192.168.1.45:49233 -> 10.0.0.20:80`}
          className="w-full h-56 bg-[#060a12] border border-slate-700/60 rounded-xl p-4 text-sm font-mono text-slate-300 placeholder-slate-600 resize-y focus:outline-none focus:ring-2 focus:ring-cyan-500/40 focus:border-cyan-500/40 transition-all custom-scrollbar"
          spellCheck={false}
          maxLength={512000}
        />

        {/* Action Buttons */}
        <div className="flex items-center gap-3 mt-4">
          <button
            id="btn-analyze-logs"
            onClick={handleAnalyze}
            disabled={isAnalyzing || !logs.trim()}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-sm font-semibold shadow-lg shadow-cyan-900/30 transition-all disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:from-cyan-600 disabled:hover:to-blue-600"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Analyze Logs
              </>
            )}
          </button>

          <button
            id="btn-load-sample"
            onClick={handleLoadSample}
            disabled={isAnalyzing}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 text-sm font-medium border border-slate-700/60 transition-all disabled:opacity-40"
          >
            <FileDown className="w-4 h-4" />
            Load Sample
          </button>

          <button
            id="btn-clear-logs"
            onClick={handleClear}
            disabled={isAnalyzing}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800/80 hover:bg-slate-700/80 text-slate-400 text-sm font-medium border border-slate-700/60 transition-all disabled:opacity-40"
          >
            <Trash2 className="w-4 h-4" />
            Clear
          </button>
        </div>
      </div>

      {/* Error State */}
      {error && (
        <div className="glass-panel rounded-2xl p-5 border border-rose-500/40 bg-gradient-to-br from-rose-950/20 to-slate-900/40">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-rose-400 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="text-sm font-semibold text-rose-300">Analysis Error</h3>
              <p className="text-sm text-slate-400 mt-1">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Loading State */}
      {isAnalyzing && (
        <div className="glass-panel rounded-2xl p-8 border border-cyan-500/30 bg-gradient-to-br from-cyan-950/20 to-slate-900/40">
          <div className="flex flex-col items-center gap-4">
            <div className="relative">
              <div className="w-16 h-16 rounded-full border-4 border-cyan-500/20 border-t-cyan-400 animate-spin" />
              <Cpu className="w-6 h-6 text-cyan-400 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
            </div>
            <div className="text-center">
              <p className="text-sm font-semibold text-slate-200">Running ML Detection Pipeline</p>
              <p className="text-xs text-slate-500 mt-1">
                Parsing logs → Feature extraction → Random Forest → XGBoost → AI Explanation
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ──────────── RESULTS ──────────── */}
      {result && !isAnalyzing && (
        <div className="space-y-5">

          {/* Security Status Banner */}
          <div className={`glass-panel rounded-2xl p-5 border ${isAttack ? 'border-rose-500/50' : 'border-emerald-500/50'} bg-gradient-to-br ${isAttack ? 'from-rose-950/30 to-slate-900/40' : 'from-emerald-950/30 to-slate-900/40'}`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className={`p-3 rounded-xl ${isAttack ? 'bg-rose-500/20' : 'bg-emerald-500/20'}`}>
                  {isAttack ? <ShieldAlert className="w-7 h-7 text-rose-400" /> : <ShieldCheck className="w-7 h-7 text-emerald-400" />}
                </div>
                <div>
                  <h3 className={`text-lg font-bold ${isAttack ? 'text-rose-300' : 'text-emerald-300'}`}>
                    {isAttack ? '⚠ THREAT DETECTED' : '✓ TRAFFIC NORMAL'}
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Analysis ID: <span className="font-mono text-slate-300">{result.analysis_id}</span>
                  </p>
                </div>
              </div>
              {isAttack && result.dominant_attack && (
                <span className={`px-3 py-1.5 rounded-lg text-sm font-bold border ${riskStyle.badge}`}>
                  {result.dominant_attack}
                </span>
              )}
            </div>
          </div>

          {/* Summary Stat Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatMini label="Events Analyzed" value={result.total_events} accent="text-cyan-400" />
            <StatMini label="Normal" value={result.normal_events} accent="text-emerald-400" />
            <StatMini label="Attacks" value={result.attack_events} accent={result.attack_events > 0 ? 'text-rose-400' : 'text-slate-400'} />
            <StatMini
              label="Risk Level"
              value={riskLevel}
              accent={riskStyle.text}
              badge
            />
          </div>

          {/* ML Detection Card */}
          {isAttack && (
            <div className="glass-panel rounded-2xl p-5 border border-cyan-500/30">
              <div className="flex items-center gap-2 mb-4">
                <Cpu className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-cyan-300 uppercase tracking-wider">
                  Detected by ML Model
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-500/30 text-cyan-300">
                  Random Forest + XGBoost
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Detection Confidence */}
                <div className="space-y-3">
                  <div>
                    <div className="text-xs text-slate-400 mb-1">Detection Confidence</div>
                    <div className="flex items-center gap-3">
                      <div className="flex-1 h-2.5 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-700"
                          style={{ width: `${(result.incident.confidence * 100).toFixed(0)}%` }}
                        />
                      </div>
                      <span className="text-sm font-bold text-cyan-300 font-mono">
                        {(result.incident.confidence * 100).toFixed(1)}%
                      </span>
                    </div>
                  </div>
                  <div className="text-xs text-slate-500">
                    Threshold: <span className="text-slate-300 font-mono">0.30</span> (30%)
                  </div>
                </div>

                {/* Classification */}
                <div>
                  <div className="text-xs text-slate-400 mb-1">Attack Classification</div>
                  <div className={`text-xl font-bold ${riskStyle.text}`}>
                    {result.incident.classification}
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    {result.attack_events} of {result.total_events} events classified as attack
                  </div>
                </div>
              </div>

              {/* Feature Evidence */}
              {result.events?.some(e => e.important_features?.length > 0) && (
                <div className="mt-5 pt-4 border-t border-slate-800/80">
                  <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5 text-amber-400" />
                    Features Contributing to Prediction
                  </div>
                  <div className="space-y-2">
                    {(result.events.find(e => e.important_features?.length > 0)?.important_features || [])
                      .slice(0, 6)
                      .map((feat, i) => (
                        <div key={i} className="flex items-center gap-3">
                          <span className="text-xs text-slate-400 w-36 truncate font-mono">{feat.feature}</span>
                          <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-gradient-to-r from-amber-500/80 to-orange-500/80 rounded-full"
                              style={{ width: `${Math.min(feat.importance * 100 * 3, 100)}%` }}
                            />
                          </div>
                          <span className="text-xs text-slate-300 font-mono w-20 text-right">
                            {typeof feat.value === 'number' ? feat.value.toLocaleString() : feat.value}
                          </span>
                          <span className="text-[10px] text-slate-500 font-mono w-12 text-right">
                            {(feat.importance * 100).toFixed(1)}%
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* AI Security Analyst Card */}
          {result.incident && (result.incident.ai_explanation_available || result.incident.summary) && (
            <div className={`glass-panel rounded-2xl p-5 border ${isAttack ? 'border-violet-500/30' : 'border-emerald-500/30'}`}>
              <div className="flex items-center gap-2 mb-4">
                <Brain className="w-4 h-4 text-violet-400" />
                <h3 className="text-sm font-bold text-violet-300 uppercase tracking-wider">
                  AI Security Analyst
                </h3>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                  result.incident.ai_explanation_available
                    ? 'bg-violet-950/60 border-violet-500/30 text-violet-300'
                    : 'bg-slate-800/60 border-slate-600/30 text-slate-400'
                }`}>
                  {result.incident.ai_explanation_available ? 'Gemini Analysis' : 'ML Summary Only'}
                </span>
              </div>

              {/* Summary */}
              {result.incident.summary && (
                <p className="text-sm text-slate-200 leading-relaxed mb-4">
                  {result.incident.summary}
                </p>
              )}

              {/* Why Detected */}
              {result.incident.why_detected?.length > 0 && (
                <div className="mb-4">
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <Target className="w-3.5 h-3.5 text-rose-400" />
                    Why was this detected?
                  </h4>
                  <ul className="space-y-1.5">
                    {result.incident.why_detected.map((reason, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                        <span className="text-rose-400 mt-1">•</span>
                        {reason}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Evidence */}
              {result.incident.evidence?.length > 0 && (
                <div className="mb-4">
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5 text-cyan-400" />
                    Evidence
                  </h4>
                  <ul className="space-y-1.5">
                    {result.incident.evidence.map((item, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                        <span className="text-cyan-400 mt-1">›</span>
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Recommended Actions */}
              {result.incident.recommended_actions?.length > 0 && (
                <div className="mb-4">
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <ArrowRight className="w-3.5 h-3.5 text-amber-400" />
                    Recommended Actions
                  </h4>
                  <ol className="space-y-1.5">
                    {result.incident.recommended_actions.map((action, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                        <span className="text-amber-400 font-mono text-xs mt-0.5 w-5 flex-shrink-0">{i + 1}.</span>
                        {action}
                      </li>
                    ))}
                  </ol>
                </div>
              )}

              {/* Analyst Note */}
              {result.incident.analyst_note && (
                <div className="mt-4 pt-3 border-t border-slate-800/60">
                  <p className="text-xs text-slate-400 italic leading-relaxed">
                    <span className="text-violet-400 not-italic font-semibold">Analyst Note: </span>
                    {result.incident.analyst_note}
                  </p>
                </div>
              )}

              {/* Confidence Note */}
              {result.incident.confidence_note && (
                <p className="text-[11px] text-slate-500 mt-3">
                  {result.incident.confidence_note}
                </p>
              )}
            </div>
          )}

          {/* Event Timeline */}
          {result.events?.length > 0 && (
            <div className="glass-panel rounded-2xl border border-slate-800/80 overflow-hidden">
              <button
                onClick={() => setShowTimeline(!showTimeline)}
                className="w-full flex items-center justify-between p-4 hover:bg-slate-900/40 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider">
                    Event Timeline
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800/80 text-slate-400 border border-slate-700/60">
                    {result.events.length} events
                  </span>
                </div>
                {showTimeline ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
              </button>

              {showTimeline && (
                <div className="overflow-x-auto custom-scrollbar">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-t border-slate-800/80 bg-[#080c16]">
                        <th className="px-4 py-2.5 text-left font-semibold text-slate-400 uppercase tracking-wider">#</th>
                        <th className="px-4 py-2.5 text-left font-semibold text-slate-400 uppercase tracking-wider">Timestamp</th>
                        <th className="px-4 py-2.5 text-left font-semibold text-slate-400 uppercase tracking-wider">Source</th>
                        <th className="px-4 py-2.5 text-left font-semibold text-slate-400 uppercase tracking-wider">Destination</th>
                        <th className="px-4 py-2.5 text-left font-semibold text-slate-400 uppercase tracking-wider">Protocol</th>
                        <th className="px-4 py-2.5 text-left font-semibold text-slate-400 uppercase tracking-wider">Result</th>
                        <th className="px-4 py-2.5 text-left font-semibold text-slate-400 uppercase tracking-wider">Type</th>
                        <th className="px-4 py-2.5 text-left font-semibold text-slate-400 uppercase tracking-wider">Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.events.map((evt, i) => {
                        const evtIsAttack = evt.prediction === 'Attack';
                        return (
                          <tr
                            key={i}
                            className={`border-t border-slate-800/40 transition-colors ${
                              evtIsAttack ? 'bg-rose-950/10 hover:bg-rose-950/20' : 'hover:bg-slate-900/40'
                            }`}
                          >
                            <td className="px-4 py-2 text-slate-500 font-mono">{i + 1}</td>
                            <td className="px-4 py-2 text-slate-300 font-mono">{evt.timestamp || '—'}</td>
                            <td className="px-4 py-2 text-slate-300 font-mono">
                              {evt.source_ip}{evt.source_port ? `:${evt.source_port}` : ''}
                            </td>
                            <td className="px-4 py-2 text-slate-300 font-mono">
                              {evt.destination_ip}{evt.destination_port ? `:${evt.destination_port}` : ''}
                            </td>
                            <td className="px-4 py-2 text-slate-300">{evt.protocol || '—'}</td>
                            <td className="px-4 py-2">
                              <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold border ${
                                evtIsAttack
                                  ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                                  : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                              }`}>
                                {evtIsAttack ? '⚠ Attack' : '✓ Normal'}
                              </span>
                            </td>
                            <td className="px-4 py-2 text-slate-300">{evt.attack_type || '—'}</td>
                            <td className="px-4 py-2 font-mono text-slate-300">
                              {(evt.detection_confidence * 100).toFixed(1)}%
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Parsing Warnings */}
          {result.parsing_warnings?.length > 0 && (
            <div className="glass-panel rounded-xl p-3 border border-amber-500/20">
              <div className="flex items-center gap-2 text-xs text-amber-400">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span className="font-semibold">Parsing Notes:</span>
                <span className="text-slate-400">{result.parsing_warnings.join(' • ')}</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Mini stat card helper ───
function StatMini({ label, value, accent, badge }) {
  return (
    <div className="glass-panel rounded-xl p-3.5 border border-slate-800/80">
      <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1">{label}</div>
      <div className={`text-xl font-bold font-mono ${accent}`}>
        {badge ? (
          <span className={`text-sm px-2.5 py-1 rounded-lg border ${getRiskStyle(value).badge}`}>{value}</span>
        ) : value}
      </div>
    </div>
  );
}
