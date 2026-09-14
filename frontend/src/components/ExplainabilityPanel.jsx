import React, { useState } from 'react';
import { ArrowLeft, CheckCircle2 } from 'lucide-react';

export default function ExplainabilityPanel({ onBackToThreat }) {
  const [actionApplied, setActionApplied] = useState(false);

  return (
    <div className="space-y-6">
      {/* Header Matching Mockup 6 */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-900 font-sans tracking-tight">
            AI Explanation
          </h2>
          <p className="text-xs text-slate-500 mt-1">
            Human-readable insights for every detection
          </p>
        </div>

        <button
          onClick={onBackToThreat}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-slate-50 text-xs font-semibold text-slate-700 shadow-xs transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Threat</span>
        </button>
      </div>

      {/* 2-Column Layout Matching Mockup 6 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column (Wide) - Detailed AI Forensic Attribution */}
        <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200/90 p-6 shadow-xs space-y-6">
          
          {/* Top Detection Summary */}
          <div className="pb-4 border-b border-slate-100 flex flex-col sm:flex-row sm:items-baseline justify-between gap-2">
            <div>
              <span className="text-xs text-slate-400 font-medium block">Detected Attack</span>
              <div className="flex items-baseline gap-3 mt-1">
                <span className="text-3xl font-extrabold text-slate-900 font-sans">
                  DDoS
                </span>
                <span className="text-sm font-semibold text-emerald-600 font-sans">
                  98% Confidence
                </span>
              </div>
            </div>

            <div className="text-xs text-slate-500 font-mono">
              Source <strong className="text-slate-900">192.168.1.10</strong> → Target <strong className="text-slate-900">8.8.8.8</strong>
            </div>
          </div>

          {/* AI Explanation Narrative */}
          <div>
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2 font-sans">
              AI Explanation
            </h4>
            <p className="text-xs text-slate-600 leading-relaxed font-sans">
              The traffic from 192.168.1.10 targeting 8.8.8.8 shows a high volume of SYN packets in a short period, which is characteristic of a Distributed Denial of Service (DDoS) attack. The source is sending connection requests without completing the handshake, leading to resource exhaustion on the target server. This pattern matches known DDoS behavior and was identified with 98% confidence by our ensemble model.
            </p>
          </div>

          {/* Key Indicators */}
          <div>
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2 font-sans">
              Key Indicators
            </h4>
            <ul className="space-y-2 text-xs text-slate-700 font-sans">
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400 shrink-0" />
                <span>High SYN packet rate</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400 shrink-0" />
                <span>Repeated requests from single source</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400 shrink-0" />
                <span>Abnormal traffic volume</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400 shrink-0" />
                <span>Matches patterns in training data (UNSW-NB15, CTU-13)</span>
              </li>
            </ul>
          </div>

          {/* MITRE ATT&CK Mapping */}
          <div className="pt-4 border-t border-slate-100">
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2.5 font-sans">
              MITRE ATT&CK Mapping
            </h4>

            <div className="space-y-2 text-xs font-sans">
              <div className="flex items-center gap-3">
                <span className="text-slate-400 w-24">Tactic</span>
                <span className="font-semibold text-slate-900">Impact (TA0040)</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-slate-400 w-24">Technique</span>
                <span className="font-semibold text-slate-900">Network Denial of Service (T1498)</span>
              </div>
              <div className="flex items-start gap-3">
                <span className="text-slate-400 w-24 shrink-0">Description</span>
                <span className="text-slate-600 leading-relaxed">
                  Adversaries may perform network denial of service to disrupt the availability of a service.
                </span>
              </div>
            </div>

            <div className="mt-3">
              <a
                href="#mitre"
                className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-700"
              >
                <span>View in MITRE ATT&CK →</span>
              </a>
            </div>
          </div>

        </div>

        {/* Right Column: Model Consensus & Suggested Actions */}
        <div className="space-y-6">
          
          {/* Model Consensus Card Matching Mockup 6 */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs">
            <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight pb-3 border-b border-slate-100 mb-3">
              Model Consensus
            </h3>

            <div className="space-y-3 text-xs font-sans">
              <div className="flex items-center justify-between py-1">
                <span className="text-slate-600">Random Forest</span>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold text-red-700 bg-red-50">
                    DDoS
                  </span>
                  <span className="font-bold text-slate-900">97%</span>
                </div>
              </div>

              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-600">LSTM</span>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold text-red-700 bg-red-50">
                    DDoS
                  </span>
                  <span className="font-bold text-slate-900">94%</span>
                </div>
              </div>

              <div className="flex items-center justify-between py-1 border-t border-slate-50">
                <span className="text-slate-600">Ensemble</span>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold text-red-700 bg-red-50">
                    DDoS
                  </span>
                  <span className="font-bold text-slate-900">98%</span>
                </div>
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-slate-200">
                <span className="font-bold text-slate-900">Final Verdict</span>
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-bold text-white bg-red-600">
                    DDoS
                  </span>
                  <span className="text-base font-extrabold text-slate-900">98%</span>
                </div>
              </div>
            </div>
          </div>

          {/* Suggested Actions Card Matching Mockup 6 */}
          <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs flex flex-col justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-900 font-sans tracking-tight pb-3 border-b border-slate-100 mb-3">
                Suggested Actions
              </h3>

              <div className="space-y-3 text-xs text-slate-700 font-sans">
                <div className="flex items-start gap-2.5">
                  <span className="w-5 h-5 rounded-full bg-slate-100 text-slate-700 font-semibold flex items-center justify-center shrink-0 text-[11px]">
                    1
                  </span>
                  <span className="mt-0.5">Block or rate-limit traffic from 192.168.1.10</span>
                </div>
                <div className="flex items-start gap-2.5">
                  <span className="w-5 h-5 rounded-full bg-slate-100 text-slate-700 font-semibold flex items-center justify-center shrink-0 text-[11px]">
                    2
                  </span>
                  <span className="mt-0.5">Monitor for similar behavior</span>
                </div>
                <div className="flex items-start gap-2.5">
                  <span className="w-5 h-5 rounded-full bg-slate-100 text-slate-700 font-semibold flex items-center justify-center shrink-0 text-[11px]">
                    3
                  </span>
                  <span className="mt-0.5">Investigate if part of a larger botnet</span>
                </div>
              </div>
            </div>

            {/* CTA Button */}
            <div className="mt-6 pt-4 border-t border-slate-100">
              <button
                onClick={() => setActionApplied(!actionApplied)}
                className={`w-full py-2.5 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center justify-center gap-2 ${
                  actionApplied
                    ? 'bg-emerald-600 text-white'
                    : 'bg-[#0f172a] hover:bg-[#1e293b] text-white shadow-xs'
                }`}
              >
                {actionApplied ? (
                  <>
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Applied Recommended Action</span>
                  </>
                ) : (
                  <span>Apply Recommended Action →</span>
                )}
              </button>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}
