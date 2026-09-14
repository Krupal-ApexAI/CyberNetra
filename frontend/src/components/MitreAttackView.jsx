import React, { useState } from 'react';
import { ExternalLink } from 'lucide-react';

export default function MitreAttackView() {
  const [selectedTechnique, setSelectedTechnique] = useState({
    id: 'T1498',
    name: 'Network Denial of Service',
    tactic: 'Impact (TA0040)',
    desc: 'Adversaries may perform network denial of service (DoS) attacks to degrade or disrupt the availability of targeted servers, services, or network infrastructure.',
    mitigation: 'Implement upstream rate limiting, enable SYN cookies, and deploy automated BGP flowspec filtering rules.'
  });

  const tactics = [
    {
      id: 'TA0001',
      name: 'Initial Access',
      techniques: [
        { id: 'T1566', name: 'Phishing', active: true },
        { id: 'T1190', name: 'Exploit Public App', active: false }
      ]
    },
    {
      id: 'TA0002',
      name: 'Execution',
      techniques: [
        { id: 'T1059', name: 'Command & Scripting', active: true },
        { id: 'T1204', name: 'User Execution', active: false }
      ]
    },
    {
      id: 'TA0004',
      name: 'Privilege Escalation',
      techniques: [
        { id: 'T1134', name: 'Access Token Manip', active: true },
        { id: 'T1068', name: 'Exploitation for PrivEsc', active: false }
      ]
    },
    {
      id: 'TA0006',
      name: 'Credential Access',
      techniques: [
        { id: 'T1558', name: 'Kerberoasting (TGS)', active: true },
        { id: 'T1003', name: 'OS Credential Dumping', active: true }
      ]
    },
    {
      id: 'TA0007',
      name: 'Discovery',
      techniques: [
        { id: 'T1018', name: 'Remote System Disc...', active: true },
        { id: 'T1046', name: 'Network Service Scan', active: false }
      ]
    },
    {
      id: 'TA0008',
      name: 'Lateral Movement',
      techniques: [
        { id: 'T1021.002', name: 'SMB / Named Pipes', active: true },
        { id: 'T1047', name: 'WMI Execution', active: true }
      ]
    },
    {
      id: 'TA0011',
      name: 'Command & Control',
      techniques: [
        { id: 'T1071', name: 'Application Layer Pro...', active: true },
        { id: 'T1573', name: 'Encrypted Channel', active: false }
      ]
    },
    {
      id: 'TA0040',
      name: 'Impact',
      techniques: [
        { id: 'T1498', name: 'Network Denial of Service', active: true },
        { id: 'T1486', name: 'Data Encrypted for Impact', active: false }
      ]
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-slate-900 font-sans tracking-tight">
            MITRE ATT&CK Matrix
          </h2>
          <p className="text-xs text-slate-500 mt-1">
            Tactics, techniques, and procedures (TTPs) mapped to real-time network flow indicators
          </p>
        </div>

        <span className="text-xs font-medium text-slate-600 bg-white border border-slate-200 px-3 py-1.5 rounded-lg shadow-xs">
          Tactics Tracked: <strong className="text-blue-600">8</strong>
        </span>
      </div>

      {/* MITRE Matrix Grid */}
      <div className="bg-white rounded-xl border border-slate-200/90 p-6 shadow-xs overflow-x-auto">
        <div className="min-w-[920px] grid grid-cols-8 gap-3">
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

                  return (
                    <button
                      key={tech.id}
                      onClick={() =>
                        setSelectedTechnique({
                          id: tech.id,
                          name: tech.name,
                          tactic: `${tactic.name} (${tactic.id})`,
                          desc: tech.active
                            ? `Active attack telemetry correlates with ${tech.name}. Adversary activity actively tagged by detection engine.`
                            : `Technique ${tech.name} monitored within baseline security audit profiles.`,
                          mitigation: tech.active
                            ? 'Trigger host isolation and update firewall drop rules.'
                            : 'Maintain continuous network flow telemetry monitoring.'
                        })
                      }
                      className={`w-full p-2.5 rounded-lg text-left border transition-all cursor-pointer ${
                        tech.active
                          ? 'bg-red-50 border-red-200 text-slate-900 hover:border-red-300'
                          : 'bg-slate-50/50 border-slate-200 text-slate-600 hover:bg-slate-100/80'
                      } ${isSelected ? 'ring-2 ring-blue-600' : ''}`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className={`text-[10px] font-mono font-bold ${tech.active ? 'text-red-700' : 'text-slate-500'}`}>
                          {tech.id}
                        </span>
                        {tech.active && (
                          <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
                        )}
                      </div>
                      <p className="text-[11px] font-semibold text-slate-800 truncate leading-tight">
                        {tech.name}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Selected Technique Inspector Panel */}
      {selectedTechnique && (
        <div className="bg-white rounded-xl border border-slate-200/90 p-5 shadow-xs space-y-3">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <div className="flex items-center gap-2.5">
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
                {selectedTechnique.id}
              </span>
              <h3 className="text-sm font-bold text-slate-900">
                {selectedTechnique.name}
              </h3>
            </div>

            <a
              href={`https://attack.mitre.org/techniques/${selectedTechnique.id.replace('.', '/')}`}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-700"
            >
              <span>MITRE ATT&CK Reference</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>

          <div className="space-y-2 text-xs font-sans">
            <div className="flex items-center gap-3">
              <span className="text-slate-400 w-24">Tactic</span>
              <span className="font-semibold text-slate-900">{selectedTechnique.tactic}</span>
            </div>
            <div className="flex items-start gap-3">
              <span className="text-slate-400 w-24 shrink-0">Description</span>
              <span className="text-slate-700 leading-relaxed">{selectedTechnique.desc}</span>
            </div>
            <div className="flex items-start gap-3">
              <span className="text-slate-400 w-24 shrink-0">Remediation</span>
              <span className="text-slate-700 leading-relaxed font-medium">{selectedTechnique.mitigation}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
