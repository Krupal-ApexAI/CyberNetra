import React, { useState, useEffect } from 'react';
import { ExternalLink, ShieldAlert, Activity, CheckCircle2 } from 'lucide-react';
import { fetchMitre } from '../services/api';

const TECHNIQUE_DETAILS = {
  'T1190': {
    desc: 'Adversaries may exploit vulnerabilities or configuration weaknesses in public-facing applications (e.g. SQL Injection against web search parameters).',
    mitigation: 'Implement parameterized prepared statements, deploy input validation filters, and enforce WAF inspection.'
  },
  'T1059': {
    desc: 'Adversaries may abuse command and script interpreters to execute arbitrary commands, scripts, or binaries on targeted host servers.',
    mitigation: 'Sanitize input before invoking system processes, avoid shell=True, and run services in restricted sandboxes.'
  },
  'T1059.007': {
    desc: 'Adversaries may inject malicious JavaScript scripts into web applications to execute code in the context of victim user browsers (Cross-Site Scripting).',
    mitigation: 'Implement strict Content Security Policy (CSP), HTML-encode dynamic outputs, and set HttpOnly on cookies.'
  },
  'T1083': {
    desc: 'Adversaries may enumerate files and directories to find sensitive information or identify targets for lateral movement and privilege escalation.',
    mitigation: 'Canonicalize file paths against a root directory, reject directory traversal tokens (../), and enforce least-privilege ACLs.'
  },
  'T1110': {
    desc: 'Adversaries may use automated credential spray, password guessing, or dictionary attacks to gain access to valid accounts.',
    mitigation: 'Enforce account lockout policies after repeated failed logins, deploy CAPTCHAs, and mandate Multi-Factor Authentication.'
  },
  'T1498': {
    desc: 'Adversaries may perform network denial of service (DoS) attacks to degrade or disrupt the availability of targeted servers, services, or network infrastructure.',
    mitigation: 'Implement upstream rate limiting, enable SYN cookies, and deploy automated BGP flowspec filtering rules.'
  },
  'T1566': {
    desc: 'Adversaries may send phishing messages with malicious attachments or links to gain initial access to victim workstations.',
    mitigation: 'Deploy email filtering, anti-spoofing DMARC/SPF/DKIM, and conduct user awareness training.'
  },
  'T1046': {
    desc: 'Adversaries may scan network services, ports, and IP ranges to identify running applications and vulnerable software versions.',
    mitigation: 'Deploy network IDS/IPS sensors to detect SYN scan surges and block hostile scanner IP ranges.'
  }
};

export default function MitreAttackView() {
  const [selectedTechnique, setSelectedTechnique] = useState({
    id: 'T1498',
    name: 'Network Denial of Service',
    tactic: 'Impact (TA0040)',
    desc: 'Adversaries may perform network denial of service (DoS) attacks to degrade or disrupt the availability of targeted servers, services, or network infrastructure.',
    mitigation: 'Implement upstream rate limiting, enable SYN cookies, and deploy automated BGP flowspec filtering rules.',
    hits: 0
  });

  const [tactics, setTactics] = useState([]);
  const [totalHits, setTotalHits] = useState(0);
  const [activeTechniques, setActiveTechniques] = useState(0);
  const [isLive, setIsLive] = useState(false);

  useEffect(() => {
    let isMounted = true;

    const poll = async () => {
      try {
        const res = await fetchMitre();
        if (!isMounted) return;

        if (res && res.data && res.data.length > 0) {
          setTactics(res.data);
          setTotalHits(res.totalHits || 0);
          setActiveTechniques(res.activeTechniques || 0);
          setIsLive(res.totalHits > 0);
        }
      } catch (err) {
        // preserve
      }
    };

    poll();
    const interval = setInterval(poll, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleSelectTechnique = (tactic, tech) => {
    const details = TECHNIQUE_DETAILS[tech.id] || {
      desc: `Adversary technique ${tech.id}: ${tech.name} mapped across monitored telemetry stream.`,
      mitigation: 'Review network segmentation and apply standard defense-in-depth security controls.'
    };

    setSelectedTechnique({
      id: tech.id,
      name: tech.name,
      tactic: `${tactic.name} (${tactic.id})`,
      desc: details.desc,
      mitigation: details.mitigation,
      hits: tech.hits || 0
    });
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="text-2xl font-bold text-slate-900 font-sans tracking-tight">
              MITRE ATT&CK Matrix
            </h2>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              {isLive ? 'LIVE TECHNIQUE TELEMETRY' : 'STATIC KNOWLEDGEBASE'}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Tactics, techniques, and procedures (TTPs) dynamically mapped to Vulnerable Lab attack executions
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-slate-600 bg-white border border-slate-200 px-3 py-1.5 rounded-lg shadow-xs">
            Techniques Active: <strong className="text-red-600 font-mono">{activeTechniques}</strong>
          </span>
          <span className="text-xs font-medium text-slate-600 bg-white border border-slate-200 px-3 py-1.5 rounded-lg shadow-xs">
            Live Hits: <strong className="text-blue-600 font-mono">{totalHits}</strong>
          </span>
        </div>
      </div>

      {/* MITRE Matrix Grid */}
      <div className="bg-white rounded-xl border border-slate-200/90 p-6 shadow-xs overflow-x-auto">
        <div className="min-w-[960px] grid grid-cols-8 gap-3">
          {tactics.map((tactic) => (
            <div key={tactic.id} className="space-y-2.5">
              {/* Tactic Column Header */}
              <div className="bg-slate-50 border border-slate-200/80 rounded-lg p-2.5 text-center">
                <span className="text-[10px] font-mono font-bold text-blue-600 block">
                  {tactic.id}
                </span>
                <span className="text-xs font-bold text-slate-900 block truncate mt-0.5">
                  {tactic.name}
                </span>
              </div>

              {/* Techniques List */}
              <div className="space-y-2">
                {tactic.techniques.map((tech) => {
                  const isSelected = selectedTechnique?.id === tech.id;
                  const hasHits = (tech.hits || 0) > 0 || tech.active;

                  return (
                    <button
                      key={tech.id}
                      onClick={() => handleSelectTechnique(tactic, tech)}
                      className={`w-full text-left p-2.5 rounded-lg border text-xs transition-all cursor-pointer relative ${
                        isSelected
                          ? 'border-blue-500 bg-blue-50/70 shadow-xs ring-1 ring-blue-500/20'
                          : hasHits
                          ? 'border-red-200 bg-red-50/70 hover:bg-red-50'
                          : 'border-slate-200/80 bg-white hover:bg-slate-50/60'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono font-semibold text-slate-400 block">
                          {tech.id}
                        </span>
                        {hasHits && (
                          <span className="px-1.5 py-0.2 rounded-full text-[9px] font-bold bg-red-100 text-red-700 font-mono">
                            {tech.hits ? `${tech.hits}x` : 'HIT'}
                          </span>
                        )}
                      </div>
                      <span
                        className={`font-semibold block mt-1 truncate ${
                          hasHits ? 'text-red-950 font-bold' : 'text-slate-700'
                        }`}
                      >
                        {tech.name}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Selected Technique Details Card */}
      {selectedTechnique && (
        <div className="bg-white rounded-xl border border-slate-200/90 p-6 shadow-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-100 gap-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold text-blue-600 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded">
                  {selectedTechnique.id}
                </span>
                <span className="text-xs text-slate-500 font-medium">
                  {selectedTechnique.tactic}
                </span>
                {selectedTechnique.hits > 0 && (
                  <span className="text-xs font-bold text-red-600 bg-red-50 border border-red-200 px-2 py-0.5 rounded">
                    {selectedTechnique.hits} Live Detections
                  </span>
                )}
              </div>
              <h3 className="text-lg font-bold text-slate-900 font-sans mt-1">
                {selectedTechnique.name}
              </h3>
            </div>

            <a
              href={`https://attack.mitre.org/techniques/${selectedTechnique.id.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-600 hover:text-blue-700 transition cursor-pointer self-start sm:self-auto"
            >
              <span>View on MITRE ATT&CK</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-4">
            <div>
              <h4 className="text-xs font-bold text-slate-900 font-sans uppercase tracking-wider mb-1.5">
                Technique Description
              </h4>
              <p className="text-xs text-slate-600 leading-relaxed">
                {selectedTechnique.desc}
              </p>
            </div>

            <div>
              <h4 className="text-xs font-bold text-slate-900 font-sans uppercase tracking-wider mb-1.5">
                Mitigation & Defense Strategy
              </h4>
              <p className="text-xs text-slate-600 leading-relaxed">
                {selectedTechnique.mitigation}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
