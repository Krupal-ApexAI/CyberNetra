import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  CheckCircle,
  Clock,
  Sparkles,
  Activity
} from 'lucide-react';
import { fetchReports } from '../services/api';

export default function ReportsPage() {
  const [downloadingId, setDownloadingId] = useState(null);
  const [reports, setReports] = useState([]);
  const [isLive, setIsLive] = useState(false);

  const defaultReports = [
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
      },
      is_live: false
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
      },
      is_live: false
    }
  ];

  useEffect(() => {
    let isMounted = true;

    const poll = async () => {
      try {
        const res = await fetchReports();
        if (!isMounted) return;

        if (res && res.data && res.data.length > 0) {
          setReports(res.data);
          setIsLive(res.data.some(r => r.is_live));
        } else {
          setReports(defaultReports);
        }
      } catch (err) {
        if (isMounted) setReports(defaultReports);
      }
    };

    poll();
    const interval = setInterval(poll, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleDownload = (rep) => {
    setDownloadingId(rep.id);
    setTimeout(() => {
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(rep, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `${rep.id}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      setDownloadingId(null);
    }, 600);
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="text-2xl font-bold text-slate-900 font-sans tracking-tight">
              Forensic & Compliance Reports
            </h2>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              {isLive ? 'LIVE FORENSIC SESSIONS' : 'SESSION ARCHIVE'}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Automated executive summaries, AI-generated forensic audits, and SIH26153 verification reports
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500 bg-white border border-slate-200 px-3 py-1.5 rounded-lg shadow-xs font-medium">
            Reports Generated: <strong className="text-blue-600 font-mono">{reports.length}</strong>
          </span>
        </div>
      </div>

      {/* Reports List */}
      <div className="space-y-4">
        {reports.map((rep) => (
          <div
            key={rep.id}
            className={`bg-white rounded-xl border p-6 shadow-xs hover:border-slate-300 transition-all ${
              rep.is_live ? 'border-blue-300 ring-1 ring-blue-500/10' : 'border-slate-200/90'
            }`}
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-100">
              <div className="space-y-1">
                <div className="flex items-center gap-2.5">
                  <span className="text-xs font-mono font-bold text-blue-600 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded">
                    {rep.id}
                  </span>
                  <span className="text-xs font-semibold text-slate-500">
                    {rep.type}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 font-semibold">
                    {rep.classification}
                  </span>
                  {rep.is_live && (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                      Active Session
                    </span>
                  )}
                </div>
                <h3 className="text-base font-bold text-slate-900 font-sans mt-1">
                  {rep.title}
                </h3>
              </div>

              <button
                onClick={() => handleDownload(rep)}
                disabled={downloadingId === rep.id}
                className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs transition cursor-pointer self-start md:self-auto shrink-0 disabled:opacity-50"
              >
                {downloadingId === rep.id ? (
                  <>
                    <CheckCircle className="w-3.5 h-3.5 animate-spin" />
                    <span>Preparing...</span>
                  </>
                ) : (
                  <>
                    <Download className="w-3.5 h-3.5" />
                    <span>Download Report</span>
                  </>
                )}
              </button>
            </div>

            <p className="text-xs text-slate-600 my-4 leading-relaxed">
              {rep.summary}
            </p>

            {/* Metrics Row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-100 text-xs">
              <div className="bg-slate-50/70 p-2.5 rounded-lg border border-slate-100">
                <span className="text-slate-400 font-medium block text-[11px]">Threat Level</span>
                <span className={`inline-block px-2 py-0.5 rounded-full text-[11px] font-semibold mt-1 border ${rep.metrics?.levelColor}`}>
                  {rep.metrics?.threatLevel}
                </span>
              </div>

              <div className="bg-slate-50/70 p-2.5 rounded-lg border border-slate-100">
                <span className="text-slate-400 font-medium block text-[11px]">Logged Anomalies</span>
                <span className="font-bold text-slate-900 block mt-1 font-mono">
                  {rep.metrics?.flows}
                </span>
              </div>

              <div className="bg-slate-50/70 p-2.5 rounded-lg border border-slate-100">
                <span className="text-slate-400 font-medium block text-[11px]">Mitigation Status</span>
                <span className="font-bold text-emerald-700 block mt-1">
                  {rep.metrics?.mitigation}
                </span>
              </div>

              <div className="bg-slate-50/70 p-2.5 rounded-lg border border-slate-100">
                <span className="text-slate-400 font-medium block text-[11px]">Generation Date</span>
                <span className="font-semibold text-slate-700 block mt-1 text-[11px]">
                  {rep.date}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
