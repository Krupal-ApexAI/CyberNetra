import React, { useState } from 'react';
import {
  FileText,
  Download,
  CheckCircle,
  Clock,
  Sparkles
} from 'lucide-react';

export default function ReportsPage() {
  const [downloadingId, setDownloadingId] = useState(null);

  const reports = [
    {
      id: 'REP-2026-0914-01',
      title: 'Real-Time Incident Forensic Assessment & Threat Audit',
      type: 'Executive Incident Briefing',
      date: '2026-09-14 14:35:00 UTC',
      classification: 'RESTRICTED // SOC-LEVEL-3',
      summary: 'Automated forensic telemetry evaluation for active threat incidents. Includes root cause timeline, affected IP inventory, and executed mitigation playbooks.',
      metrics: {
        threatLevel: 'Critical',
        levelColor: 'text-red-700 bg-red-50 border-red-200',
        flows: '1,420 Anomalies',
        flowsColor: 'text-slate-900 bg-slate-50 border-slate-200',
        mitigation: '100% Contained',
        mitColor: 'text-emerald-700 bg-emerald-50 border-emerald-200'
      }
    },
    {
      id: 'REP-2026-0914-02',
      title: 'NTRO SIH26153 Model Precision & Latency Compliance Report',
      type: 'AI Validation Audit',
      date: '2026-09-14 12:00:00 UTC',
      classification: 'OFFICIAL // SIH26153',
      summary: 'Comprehensive testing results across XGBoost, Random Forest, and Deep Sequence models on CIC-IDS2017 benchmark dataset. Precision: 98.6%, Average Inference Latency: 12.4ms.',
      metrics: {
        threatLevel: 'Nominal',
        levelColor: 'text-emerald-700 bg-emerald-50 border-emerald-200',
        flows: '0 Anomalies',
        flowsColor: 'text-slate-900 bg-slate-50 border-slate-200',
        mitigation: 'All Systems Normal',
        mitColor: 'text-emerald-700 bg-emerald-50 border-emerald-200'
      }
    },
    {
      id: 'REP-2026-0913-03',
      title: 'Weekly SOC Attack Surface & Ingress Flow Summary',
      type: 'Weekly Digest',
      date: '2026-09-13 23:59:59 UTC',
      classification: 'INTERNAL ONLY',
      summary: 'Aggregated packet analysis covering 4.8M flows. 99.4% benign traffic ratio with 24 blocked brute-force sweeps.',
      metrics: {
        threatLevel: 'Low',
        levelColor: 'text-emerald-700 bg-emerald-50 border-emerald-200',
        flows: '156 Anomalies',
        flowsColor: 'text-slate-900 bg-slate-50 border-slate-200',
        mitigation: '100% Mitigated',
        mitColor: 'text-emerald-700 bg-emerald-50 border-emerald-200'
      }
    }
  ];

  const handleDownload = (rep) => {
    setDownloadingId(rep.id);
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(rep, null, 2));
    const a = document.createElement('a');
    a.href = dataStr;
    a.download = `${rep.id}_Report.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => setDownloadingId(null), 1000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-900 font-sans tracking-tight">
            Reports & Compliance Audits
          </h2>
          <p className="text-xs text-slate-500 mt-1">
            Executive incident briefings, SIH26153 benchmark validation, and forensic archives
          </p>
        </div>

        <button
          onClick={() => handleDownload(reports[0])}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-xs transition-all cursor-pointer"
        >
          <Sparkles className="w-3.5 h-3.5" />
          <span>Generate Live Briefing PDF</span>
        </button>
      </div>

      {/* Reports List */}
      <div className="space-y-4">
        {reports.map((rep) => (
          <div
            key={rep.id}
            className="bg-white rounded-xl border border-slate-200/90 p-6 shadow-xs space-y-4 hover:border-slate-300 transition-all"
          >
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-100 gap-2">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
                    {rep.id}
                  </span>
                  <span className="text-xs text-slate-500 font-medium">
                    {rep.type}
                  </span>
                </div>
                <h3 className="text-base font-bold text-slate-900 mt-1.5 font-sans">
                  {rep.title}
                </h3>
              </div>

              <div className="flex items-center gap-1.5 text-xs text-slate-500 font-medium">
                <Clock className="w-3.5 h-3.5" />
                <span>{rep.date}</span>
              </div>
            </div>

            <p className="text-xs text-slate-600 leading-relaxed font-sans">
              {rep.summary}
            </p>

            {/* Clean Light Theme Metrics Grid (NO ugly dark gray bars!) */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="bg-slate-50 border border-slate-200/80 rounded-lg p-3">
                <span className="text-[11px] font-medium text-slate-500 block">Threat Posture</span>
                <span className={`inline-block mt-1 text-xs font-bold px-2 py-0.5 rounded border ${rep.metrics.levelColor}`}>
                  {rep.metrics.threatLevel}
                </span>
              </div>

              <div className="bg-slate-50 border border-slate-200/80 rounded-lg p-3">
                <span className="text-[11px] font-medium text-slate-500 block">Telemetry Evaluated</span>
                <span className="text-xs font-bold text-slate-900 block mt-1">
                  {rep.metrics.flows}
                </span>
              </div>

              <div className="bg-slate-50 border border-slate-200/80 rounded-lg p-3">
                <span className="text-[11px] font-medium text-slate-500 block">Containment Status</span>
                <span className={`inline-block mt-1 text-xs font-bold px-2 py-0.5 rounded border ${rep.metrics.mitColor}`}>
                  {rep.metrics.mitigation}
                </span>
              </div>
            </div>

            {/* Footer */}
            <div className="flex items-center justify-between pt-2 border-t border-slate-100">
              <span className="text-[11px] text-slate-400 font-medium">
                Classification: <strong className="text-slate-600">{rep.classification}</strong>
              </span>

              <button
                onClick={() => handleDownload(rep)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-semibold shadow-xs transition-colors cursor-pointer"
              >
                {downloadingId === rep.id ? (
                  <>
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-600" />
                    <span>Exporting...</span>
                  </>
                ) : (
                  <>
                    <Download className="w-3.5 h-3.5 text-blue-600" />
                    <span>Download Report</span>
                  </>
                )}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
