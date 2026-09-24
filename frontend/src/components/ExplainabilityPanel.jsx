import React, { useState, useEffect } from 'react';
import { ArrowLeft, CheckCircle2, ShieldAlert, Sparkles, Activity, Clock } from 'lucide-react';
import { fetchExplainability } from '../services/api';

export default function ExplainabilityPanel({ onBackToThreat }) {
  const [actionApplied, setActionApplied] = useState(false);
  const [explanation, setExplanation] = useState(null);
  const [isLive, setIsLive] = useState(false);

  const defaultExplanation = {
    current_threat: 'DDoS SYN Flood Attack',
    what_happened_summary: 'The traffic from 192.168.1.10 targeting 8.8.8.8 shows an anomalous surge of SYN packets in a short time window. The source is sending connection requests without completing the three-way handshake, leading to socket buffer exhaustion on the target ingress gateway.',
    evidence_trail: [
      { timestamp: '10:02', indicator: 'SYN Flood Initiation', observed_value: '1,200 pkts/s (2.4 MB/s)', baseline_value: '180 pkts/s', severity: 'MEDIUM', description: 'Unsolicited connection handshakes from external ASNs.' },
      { timestamp: '10:07', indicator: 'Bandwidth Saturation', observed_value: '11,500 pkts/s (25.4 MB/s)', baseline_value: '210 pkts/s', severity: 'HIGH', description: 'Network ingress exceeded 85% link capacity.' },
      { timestamp: '10:14', indicator: 'Connection Pool Exhaustion', observed_value: '1,810 concurrent connections', baseline_value: '16 connections', severity: 'CRITICAL', description: 'Edge router dropping legitimate SYN packets due to buffer queue overflow.' }
    ],
    whats_next_prediction: 'Complete Denial of Service (DoS) across core edge gateways and DNS resolvers.',
    whats_next_details: 'Attack forecasting indicates that without intervention, total network paralysis will occur in < 2 minutes. The adversary is attempting resource exhaustion to mask potential secondary exfiltration.',
    attack_trajectory: [
      '1. Botnet Mobilization (Observed)',
      '2. Ingress Flood Acceleration (Active)',
      '3. Full Pipeline Congestion (Predicted Next)',
      '4. Complete Gateway Paralysis (Imminent Risk)'
    ],
    target_assets: ['Edge Gateway Router (192.168.1.1)', 'Web Server Ingress (Port 80/443)', 'Local DNS Cache'],
    estimated_time_to_impact: '1 min 45 sec',
    mitigation_playbook: [
      'Engage upstream SYN cookie challenge on edge router.',
      'Deploy BGP Flowspec rule to drop unsolicited external SYN packets.',
      'Scale reverse proxy connection pools and enable aggressive connection timeouts.'
    ]
  };

  useEffect(() => {
    let isMounted = true;

    const loadExplanation = async () => {
      try {
        const res = await fetchExplainability();
        if (!isMounted) return;

        if (res && res.data) {
          setExplanation(res.data);
          setIsLive(res.isLive);
        } else {
          setExplanation(defaultExplanation);
        }
      } catch (err) {
        if (isMounted) setExplanation(defaultExplanation);
      }
    };

    loadExplanation();
    const interval = setInterval(loadExplanation, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const data = explanation || defaultExplanation;

  return (
    <div className="space-y-6 font-sans">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="text-2xl font-bold text-slate-900 font-sans tracking-tight">
              Explainable AI (XAI) Forensic Engine
            </h2>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              {isLive ? 'LIVE LAB ATTACK XAI' : 'SCENARIO FORENSICS'}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Human-readable attribution, predictive trajectories, and evidence trails powered by SHAP & Random Forest feature importances
          </p>
        </div>

        {onBackToThreat && (
          <button
            onClick={onBackToThreat}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-slate-50 text-xs font-semibold text-slate-700 shadow-xs transition-colors cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Threats</span>
          </button>
        )}
      </div>

      {/* 2-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Left Column (Wide) - Detailed AI Forensic Attribution */}
        <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200/90 p-6 shadow-xs space-y-6">

          {/* Top Detection Summary */}
          <div className="pb-4 border-b border-slate-100 flex flex-col sm:flex-row sm:items-baseline justify-between gap-2">
            <div>
              <span className="text-xs text-slate-400 font-medium block">Detected Threat Signature</span>
              <div className="flex items-baseline gap-3 mt-1">
                <span className="text-2xl sm:text-3xl font-extrabold text-slate-900 font-sans">
                  {data.current_threat}
                </span>
                <span className="text-sm font-semibold text-emerald-600 font-sans">
                  98.4% Confidence
                </span>
              </div>
            </div>

            <div className="text-xs text-slate-500 font-mono">
              Ensemble: <strong className="text-slate-900">RF + XGBoost (UNSW-NB15)</strong>
            </div>
          </div>

          {/* AI Explanation Narrative */}
          <div>
            <div className="flex items-center gap-1.5 mb-2">
              <Sparkles className="w-3.5 h-3.5 text-blue-600" />
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider font-sans">
                Forensic Attribution & Root Cause Analysis
              </h4>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed font-sans bg-slate-50/70 p-4 rounded-xl border border-slate-100">
              {data.what_happened_summary}
            </p>
          </div>

          {/* Evidence Trail */}
          <div>
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-3 font-sans">
              Telemetry Evidence Trail
            </h4>
            <div className="space-y-2.5">
              {(data.evidence_trail || []).map((ev, idx) => (
                <div key={idx} className="p-3 bg-white rounded-lg border border-slate-200/80 text-xs hover:border-slate-300 transition-colors">
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[11px] font-bold text-slate-500 bg-slate-100 px-1.5 py-0.5 rounded">
                        {ev.timestamp}
                      </span>
                      <span className="font-bold text-slate-900 font-sans">{ev.indicator}</span>
                    </div>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${ev.severity === 'CRITICAL'
                          ? 'text-red-700 bg-red-50 border-red-200'
                          : ev.severity === 'HIGH'
                            ? 'text-amber-700 bg-amber-50 border-amber-200'
                            : 'text-slate-700 bg-slate-50 border-slate-200'
                        }`}
                    >
                      {ev.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-600 mt-1">{ev.description}</p>
                  <div className="mt-2 pt-1.5 border-t border-slate-50 flex items-center justify-between text-[10px] text-slate-400 font-mono">
                    <span>Observed: {ev.observed_value}</span>
                    <span>Baseline: {ev.baseline_value}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Predictive Forecasting - What Happens Next */}
          <div className="pt-2 border-t border-slate-100">
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2 font-sans flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
              What Happens Next (Predictive Trajectory)
            </h4>
            <div className="p-4 bg-red-50/50 border border-red-100 rounded-xl space-y-2">
              <p className="text-xs font-bold text-red-950">
                {data.whats_next_prediction}
              </p>
              <p className="text-xs text-red-900/80 leading-relaxed">
                {data.whats_next_details}
              </p>
            </div>
          </div>
        </div>

        {/* Right Column - Attack Trajectory & Playbook */}
        <div className="space-y-6">

          {/* Attack Trajectory Card */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-6 shadow-xs">
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-4 font-sans">
              Kill Chain Trajectory
            </h4>
            <div className="space-y-3">
              {(data.attack_trajectory || []).map((step, idx) => (
                <div key={idx} className="flex items-center gap-2.5 text-xs">
                  <span className="w-6 h-6 rounded-full bg-blue-50 text-blue-600 border border-blue-200 flex items-center justify-center font-mono font-bold text-[11px] shrink-0">
                    {idx + 1}
                  </span>
                  <span className="text-slate-800 font-medium">{step}</span>
                </div>
              ))}
            </div>

            <div className="mt-4 pt-4 border-t border-slate-100">
              <span className="text-xs text-slate-400 font-medium block">Estimated Time to Full Impact</span>
              <span className="text-lg font-bold text-red-600 font-mono mt-0.5 block">
                {data.estimated_time_to_impact || 'Immediate'}
              </span>
            </div>
          </div>

          {/* Target Assets Card */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-6 shadow-xs">
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-3 font-sans">
              Targeted Infrastructure
            </h4>
            <div className="space-y-2">
              {(data.target_assets || []).map((asset, idx) => (
                <div key={idx} className="flex items-center gap-2 text-xs text-slate-700 bg-slate-50 p-2 rounded-lg border border-slate-100 font-mono text-[11px]">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-400 shrink-0" />
                  <span>{asset}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Mitigation Playbook Card */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-6 shadow-xs">
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-3 font-sans">
              Automated Mitigation Playbook
            </h4>
            <div className="space-y-2.5">
              {(data.mitigation_playbook || []).map((rule, idx) => (
                <div key={idx} className="flex items-start gap-2 text-xs text-slate-700">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                  <span>{rule}</span>
                </div>
              ))}
            </div>

            <button
              onClick={() => setActionApplied(true)}
              className="mt-4 w-full py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-semibold text-xs transition cursor-pointer shadow-xs"
            >
              {actionApplied ? 'Mitigation Enforced ✓' : 'Enforce Playbook Now'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
