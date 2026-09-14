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

// ─── Risk level styling (Clean High-Contrast Light Theme) ───
const RISK_STYLES = {
  CRITICAL: {
    bg: 'bg-rose-50',
    border: 'border-rose-200',
    text: 'text-rose-600',
    badge: 'bg-rose-100 text-rose-700 border-rose-300'
  },
  HIGH: {
    bg: 'bg-orange-50',
    border: 'border-orange-200',
    text: 'text-orange-600',
    badge: 'bg-orange-100 text-orange-700 border-orange-300'
  },
  MEDIUM: {
    bg: 'bg-amber-50',
    border: 'border-amber-200',
    text: 'text-amber-600',
    badge: 'bg-amber-100 text-amber-700 border-amber-300'
  },
  LOW: {
    bg: 'bg-emerald-50',
    border: 'border-emerald-200',
    text: 'text-emerald-600',
    badge: 'bg-emerald-100 text-emerald-700 border-emerald-300'
  },
};

const getRiskStyle = (level) => RISK_STYLES[level] || RISK_STYLES.MEDIUM;

export default function LogAnalysis({ initialMeta }) {
  const [logs, setLogs] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [showTimeline, setShowTimeline] = useState(false);

  // Auto-populate logs if an IP was passed from Network Graph or search
  React.useEffect(() => {
    if (initialMeta?.ip) {
      const ip = initialMeta.ip.split(':')[0]; // strip port if present
      const sample = SAMPLE_LOGS.split('\n').map(l => l.replace('192.168.1.45', ip)).join('\n');
      setLogs(sample);
    }
  }, [initialMeta]);

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
      {/* Header Banner matching Mockup reference */}
      <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs flex items-center justify-between">
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-purple-50 border border-purple-200 flex items-center justify-center text-purple-600 shadow-xs">
            <ScrollText className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-900 font-sans tracking-tight">Log Analysis</h2>
            <p className="text-xs text-slate-500 mt-0.5">ML-powered intrusion detection with AI-generated security explanations</p>
          </div>
        </div>
      </div>

      {/* Input Section */}
      <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs">
        <div className="flex items-center justify-between mb-3">
          <label className="text-xs font-bold text-slate-900 flex items-center gap-2">
            <ScrollText className="w-4 h-4 text-cyan-600" />
            <span>Network Log Input</span>
          </label>
          <div className="flex items-center gap-3 text-xs text-slate-500 font-mono">
            <span>{lineCount} lines</span>
            <span>•</span>
            <span>{charCount.toLocaleString()} chars</span>
          </div>
        </div>

        {/* Sleek Dark Console Textarea matching Reference Mockup */}
        <textarea
          id="log-input-textarea"
          value={logs}
          onChange={(e) => setLogs(e.target.value)}
          placeholder={`Paste network logs here...\n\n2026-09-11 00:42:16 TCP 192.168.1.45:49231 -> 10.0.0.20:80\n2026-09-11 00:42:17 TCP 192.168.1.45:49232 -> 10.0.0.20:80\n2026-09-11 00:42:17 TCP 192.168.1.45:49233 -> 10.0.0.20:80`}
          className="w-full h-52 bg-[#0b101b] border border-slate-800 rounded-xl p-4 text-xs font-mono text-cyan-300 placeholder-slate-600 resize-y focus:outline-none focus:border-cyan-500/80 focus:ring-2 focus:ring-cyan-500/20 transition-all custom-scrollbar leading-relaxed"
          spellCheck={false}
          maxLength={512000}
        />

        {/* Action Buttons matching Reference Mockup */}
        <div className="flex items-center gap-2.5 mt-4">
          <button
            id="btn-analyze-logs"
            onClick={handleAnalyze}
            disabled={isAnalyzing || !logs.trim()}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-sky-400 to-blue-600 hover:from-sky-500 hover:to-blue-700 text-white text-xs font-semibold shadow-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Analyze Logs</span>
              </>
            )}
          </button>

          <button
            id="btn-load-sample"
            onClick={handleLoadSample}
            disabled={isAnalyzing}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 text-xs font-medium shadow-xs transition-all cursor-pointer"
          >
            <FileDown className="w-3.5 h-3.5 text-slate-400" />
            <span>Load Sample</span>
          </button>

          <button
            id="btn-clear-logs"
            onClick={handleClear}
            disabled={isAnalyzing || !logs}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 text-xs font-medium shadow-xs transition-all disabled:opacity-40 cursor-pointer"
          >
            <Trash2 className="w-3.5 h-3.5 text-slate-400" />
            <span>Clear</span>
          </button>
        </div>
      </div>

      {/* Error State */}
      {error && (
        <div className="bg-rose-50 rounded-xl p-5 border border-rose-200 shadow-xs">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-rose-600 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="text-sm font-semibold text-rose-800">Analysis Error</h3>
              <p className="text-xs text-rose-700 mt-1">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Loading State */}
      {isAnalyzing && (
        <div className="bg-white rounded-xl p-8 border border-slate-200 shadow-xs">
          <div className="flex flex-col items-center gap-4">
            <div className="relative">
              <div className="w-14 h-14 rounded-full border-4 border-blue-100 border-t-blue-600 animate-spin" />
              <Cpu className="w-5 h-5 text-blue-600 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
            </div>
            <div className="text-center">
              <p className="text-sm font-bold text-slate-900">Running ML Detection Pipeline</p>
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

          {/* Security Status Banner - Crisp Light Theme */}
          <div className={`rounded-xl p-5 border shadow-xs ${
            isAttack ? 'bg-rose-50/80 border-rose-200' : 'bg-emerald-50/80 border-emerald-200'
          }`}>
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div className="flex items-center gap-3.5">
                <div className={`p-3 rounded-xl ${
                  isAttack ? 'bg-rose-100 text-rose-600' : 'bg-emerald-100 text-emerald-600'
                }`}>
                  {isAttack ? <ShieldAlert className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
                </div>
                <div>
                  <h3 className={`text-base font-bold tracking-tight ${
                    isAttack ? 'text-rose-700' : 'text-emerald-700'
                  }`}>
                    {isAttack ? '⚠ THREAT DETECTED' : '✓ TRAFFIC NORMAL'}
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Analysis ID: <span className="font-mono text-slate-800 font-semibold">{result.analysis_id}</span>
                  </p>
                </div>
              </div>
              {isAttack && result.dominant_attack && (
                <span className="px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider bg-rose-100 text-rose-700 border border-rose-300 shadow-xs">
                  {result.dominant_attack}
                </span>
              )}
            </div>
          </div>

          {/* Summary Stat Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatMini label="Events Analyzed" value={result.total_events} accent="text-slate-900" />
            <StatMini label="Normal" value={result.normal_events} accent="text-emerald-600" />
            <StatMini
              label="Attacks"
              value={result.attack_events}
              accent={result.attack_events > 0 ? 'text-rose-600' : 'text-slate-900'}
            />
            <StatMini
              label="Risk Level"
              value={riskLevel}
              accent={riskStyle.text}
              badge
            />
          </div>

          {/* ML Detection Card */}
          {isAttack && (
            <div className="bg-white rounded-xl p-6 border border-slate-200/90 shadow-xs">
              <div className="flex items-center gap-2 mb-5">
                <Cpu className="w-4 h-4 text-blue-600" />
                <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                  Detected by ML Model
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-50 border border-blue-200 text-blue-700 font-semibold">
                  Random Forest + XGBoost
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Detection Confidence */}
                <div className="space-y-3">
                  <div>
                    <div className="text-xs font-semibold text-slate-700 mb-1.5">Detection Confidence</div>
                    <div className="flex items-center gap-3">
                      <div className="flex-1 h-2.5 bg-slate-100 rounded-full border border-slate-200/80 overflow-hidden">
                        <div
                          className="h-full bg-blue-600 rounded-full transition-all duration-700"
                          style={{ width: `${(result.incident.confidence * 100).toFixed(0)}%` }}
                        />
                      </div>
                      <span className="text-sm font-bold text-slate-900 font-mono">
                        {(result.incident.confidence * 100).toFixed(1)}%
                      </span>
                    </div>
                  </div>
                  <div className="text-xs text-slate-500">
                    Threshold: <span className="text-slate-700 font-mono font-semibold">0.30</span> (30%)
                  </div>
                </div>

                {/* Classification */}
                <div>
                  <div className="text-xs font-semibold text-slate-700 mb-1">Attack Classification</div>
                  <div className="text-2xl font-bold text-rose-600 font-sans tracking-tight">
                    {result.incident.classification}
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    {result.attack_events} of {result.total_events} events classified as attack
                  </div>
                </div>
              </div>

              {/* Feature Evidence with Clean Light Progress Bars */}
              {result.events?.some(e => e.important_features?.length > 0) && (
                <div className="mt-6 pt-5 border-t border-slate-100">
                  <div className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-3.5 flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5 text-amber-500" />
                    Features Contributing to Prediction
                  </div>
                  <div className="space-y-2.5">
                    {(result.events.find(e => e.important_features?.length > 0)?.important_features || [])
                      .slice(0, 6)
                      .map((feat, i) => (
                        <div key={i} className="flex items-center gap-3">
                          <span className="text-xs text-slate-700 font-mono font-medium w-36 truncate">
                            {feat.feature}
                          </span>
                          <div className="flex-1 h-2 bg-slate-100 rounded-full border border-slate-200/70 overflow-hidden">
                            <div
                              className="h-full bg-gradient-to-r from-amber-500 to-orange-500 rounded-full transition-all"
                              style={{ width: `${Math.min(feat.importance * 100 * 3, 100)}%` }}
                            />
                          </div>
                          <span className="text-xs text-slate-900 font-mono font-bold w-20 text-right">
                            {typeof feat.value === 'number' ? feat.value.toLocaleString() : feat.value}
                          </span>
                          <span className="text-[11px] text-slate-500 font-mono font-medium w-12 text-right">
                            {(feat.importance * 100).toFixed(1)}%
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* AI Security Analyst Card - High Contrast Light Theme */}
          {result.incident && (result.incident.ai_explanation_available || result.incident.summary) && (
            <div className="bg-white rounded-xl p-6 border border-slate-200/90 shadow-xs space-y-4">
              <div className="flex items-center gap-2 mb-2">
                <Brain className="w-4 h-4 text-purple-600" />
                <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                  AI Security Analyst
                </h3>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${
                  result.incident.ai_explanation_available
                    ? 'bg-purple-50 border-purple-200 text-purple-700'
                    : 'bg-slate-100 border-slate-200 text-slate-600'
                }`}>
                  {result.incident.ai_explanation_available ? 'Gemini Analysis' : 'ML Summary Only'}
                </span>
              </div>

              {/* Summary narrative */}
              {result.incident.summary && (
                <p className="text-xs sm:text-sm text-slate-800 leading-relaxed font-normal">
                  {result.incident.summary}
                </p>
              )}

              {/* Why Detected */}
              {result.incident.why_detected?.length > 0 && (
                <div className="pt-2">
                  <h4 className="text-xs font-bold text-rose-600 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <Target className="w-3.5 h-3.5 text-rose-500" />
                    Why was this detected?
                  </h4>
                  <ul className="space-y-1.5">
                    {result.incident.why_detected.map((reason, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-slate-700 leading-relaxed">
                        <span className="text-rose-500 font-bold mt-0.5">•</span>
                        <span>{reason}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Evidence */}
              {result.incident.evidence?.length > 0 && (
                <div className="pt-2">
                  <h4 className="text-xs font-bold text-blue-600 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5 text-blue-500" />
                    Evidence
                  </h4>
                  <ul className="space-y-1.5">
                    {result.incident.evidence.map((item, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-slate-700 leading-relaxed">
                        <span className="text-blue-500 font-bold mt-0.5">›</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Recommended Actions */}
              {result.incident.recommended_actions?.length > 0 && (
                <div className="pt-2">
                  <h4 className="text-xs font-bold text-amber-600 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <ArrowRight className="w-3.5 h-3.5 text-amber-500" />
                    Recommended Actions
                  </h4>
                  <ol className="space-y-1.5">
                    {result.incident.recommended_actions.map((action, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-slate-700 leading-relaxed">
                        <span className="text-amber-600 font-mono font-bold mt-0.5 w-4 flex-shrink-0">
                          {i + 1}.
                        </span>
                        <span>{action}</span>
                      </li>
                    ))}
                  </ol>
                </div>
              )}

              {/* Analyst Note */}
              {result.incident.analyst_note && (
                <div className="mt-4 pt-3 border-t border-slate-100">
                  <p className="text-xs text-slate-700 italic leading-relaxed">
                    <span className="text-purple-700 not-italic font-bold">Analyst Note: </span>
                    {result.incident.analyst_note}
                  </p>
                </div>
              )}

              {/* Confidence Note */}
              {result.incident.confidence_note && (
                <p className="text-[11px] text-slate-500 pt-1">
                  {result.incident.confidence_note}
                </p>
              )}
            </div>
          )}

          {/* Event Timeline Table with Crisp Light Theme */}
          {result.events?.length > 0 && (
            <div className="bg-white rounded-xl border border-slate-200/90 shadow-xs overflow-hidden">
              <button
                onClick={() => setShowTimeline(!showTimeline)}
                className="w-full flex items-center justify-between p-4 bg-slate-50/70 hover:bg-slate-100/70 transition-colors cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4 text-blue-600" />
                  <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                    Event Timeline
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white text-slate-600 border border-slate-200 font-semibold">
                    {result.events.length} events
                  </span>
                </div>
                {showTimeline ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
              </button>

              {showTimeline && (
                <div className="overflow-x-auto custom-scrollbar border-t border-slate-200">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="bg-slate-50/90 text-slate-600 font-semibold uppercase tracking-wider text-[11px] border-b border-slate-200">
                        <th className="px-4 py-2.5 text-left">#</th>
                        <th className="px-4 py-2.5 text-left">Timestamp</th>
                        <th className="px-4 py-2.5 text-left">Source</th>
                        <th className="px-4 py-2.5 text-left">Destination</th>
                        <th className="px-4 py-2.5 text-left">Protocol</th>
                        <th className="px-4 py-2.5 text-left">Result</th>
                        <th className="px-4 py-2.5 text-left">Type</th>
                        <th className="px-4 py-2.5 text-left">Confidence</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {result.events.map((evt, i) => {
                        const evtIsAttack = evt.prediction === 'Attack';
                        return (
                          <tr
                            key={i}
                            className={`transition-colors font-mono ${
                              evtIsAttack ? 'bg-rose-50/40 hover:bg-rose-50/70' : 'hover:bg-slate-50/80'
                            }`}
                          >
                            <td className="px-4 py-2.5 text-slate-500">{i + 1}</td>
                            <td className="px-4 py-2.5 text-slate-700">{evt.timestamp || '—'}</td>
                            <td className="px-4 py-2.5 text-slate-900 font-medium">
                              {evt.source_ip}{evt.source_port ? `:${evt.source_port}` : ''}
                            </td>
                            <td className="px-4 py-2.5 text-slate-900 font-medium">
                              {evt.destination_ip}{evt.destination_port ? `:${evt.destination_port}` : ''}
                            </td>
                            <td className="px-4 py-2.5 text-slate-700">{evt.protocol || '—'}</td>
                            <td className="px-4 py-2.5">
                              <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${
                                evtIsAttack
                                  ? 'bg-rose-100 text-rose-700 border-rose-200'
                                  : 'bg-emerald-100 text-emerald-700 border-emerald-200'
                              }`}>
                                {evtIsAttack ? '⚠ Attack' : '✓ Normal'}
                              </span>
                            </td>
                            <td className="px-4 py-2.5 text-slate-700 font-sans">{evt.attack_type || '—'}</td>
                            <td className="px-4 py-2.5 font-bold text-slate-900">
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
            <div className="bg-amber-50 rounded-xl p-3.5 border border-amber-200">
              <div className="flex items-center gap-2 text-xs text-amber-800">
                <AlertTriangle className="w-4 h-4 text-amber-600" />
                <span className="font-bold">Parsing Notes:</span>
                <span className="text-amber-700">{result.parsing_warnings.join(' • ')}</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Mini stat card helper with crisp typography ───
function StatMini({ label, value, accent, badge }) {
  return (
    <div className="bg-white rounded-xl p-4 border border-slate-200/90 shadow-xs">
      <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-1.5">
        {label}
      </div>
      <div className={`text-2xl font-bold font-mono ${accent}`}>
        {badge ? (
          <span className={`text-xs px-2.5 py-1 rounded-md border font-bold uppercase tracking-wider ${getRiskStyle(value).badge}`}>
            {value}
          </span>
        ) : value}
      </div>
    </div>
  );
}
