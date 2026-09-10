import React from 'react';
import { ShieldAlert, ShieldCheck, AlertCircle, AlertTriangle } from 'lucide-react';

export default function RiskScore({ score, level, confidence }) {
  const safeScore = score ?? 12;
  const safeLevel = level ?? 'LOW';
  const safeConfidence = confidence ?? 95;

  // Clamp score between 0 and 100
  const normalizedScore = Math.min(Math.max(safeScore, 0), 100);

  // SVG circular arc calculations
  const size = 180;
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  // Use a 270 degree arc for gauge effect
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  const getTheme = () => {
    if (normalizedScore >= 85 || level === 'CRITICAL') {
      return {
        label: 'CRITICAL RISK',
        color: '#f43f5e',
        glow: 'drop-shadow(0 0 16px rgba(244, 63, 94, 0.45))',
        badgeBg: 'bg-rose-950/80 text-rose-400 border-rose-500/50',
        textColor: 'text-rose-400',
        icon: ShieldAlert,
        description: 'Imminent service degradation or root exploit threshold reached'
      };
    }
    if (normalizedScore >= 65 || level === 'HIGH') {
      return {
        label: 'HIGH RISK',
        color: '#f97316',
        glow: 'drop-shadow(0 0 16px rgba(249, 115, 22, 0.45))',
        badgeBg: 'bg-orange-950/80 text-orange-400 border-orange-500/50',
        textColor: 'text-orange-400',
        icon: AlertTriangle,
        description: 'Multi-stage progression in action; rapid containment advised'
      };
    }
    if (normalizedScore >= 35 || level === 'MEDIUM') {
      return {
        label: 'MEDIUM RISK',
        color: '#f59e0b',
        glow: 'drop-shadow(0 0 16px rgba(245, 158, 11, 0.45))',
        badgeBg: 'bg-amber-950/80 text-amber-400 border-amber-500/50',
        textColor: 'text-amber-400',
        icon: AlertCircle,
        description: 'Suspicious scan activity flagged; monitoring endpoints closely'
      };
    }
    return {
      label: 'LOW RISK',
      color: '#10b981',
      glow: 'drop-shadow(0 0 16px rgba(16, 185, 129, 0.45))',
      badgeBg: 'bg-emerald-950/80 text-emerald-400 border-emerald-500/50',
      textColor: 'text-emerald-400',
      icon: ShieldCheck,
      description: 'Traffic flow complies with trained normal behavior baseline'
    };
  };

  const theme = getTheme();
  const Icon = theme.icon;

  return (
    <div className="w-full glass-panel rounded-2xl p-5 border border-slate-800/80 flex flex-col items-center justify-between">
      {/* Header */}
      <div className="w-full flex items-center justify-between pb-3 mb-2 border-b border-slate-800/60">
        <div className="flex items-center gap-2">
          <Icon className={`w-4 h-4 ${theme.textColor}`} />
          <h3 className="text-sm font-semibold tracking-wide text-slate-200">
            Composite Threat Risk Index
          </h3>
        </div>
        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${theme.badgeBg}`}>
          {theme.label}
        </span>
      </div>

      {/* SVG Radial Gauge */}
      <div className="relative my-3 flex items-center justify-center">
        <svg
          width={size}
          height={size}
          className="transform -rotate-90"
          style={{ filter: theme.glow }}
        >
          {/* Background circle track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Progress circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={theme.color}
            strokeWidth={strokeWidth}
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Score Readout */}
        <div className="absolute flex flex-col items-center justify-center text-center">
          <span className={`text-4xl sm:text-5xl font-black font-mono tracking-tighter ${theme.textColor}`}>
            {normalizedScore}
          </span>
          <span className="text-[10px] uppercase font-mono tracking-widest text-slate-400 font-medium">
            OUT OF 100
          </span>
        </div>
      </div>

      {/* Summary Description & Confidence */}
      <div className="w-full text-center mt-2 pt-3 border-t border-slate-800/60">
        <p className="text-xs text-slate-300 font-medium line-clamp-2">
          {theme.description}
        </p>
        <div className="mt-2.5 flex items-center justify-between text-[11px] text-slate-500 font-mono">
          <span>Model Certainty</span>
          <span className="text-cyan-400 font-bold">{confidence}% Confidence</span>
        </div>
      </div>
    </div>
  );
}
