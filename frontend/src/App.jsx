import React, { useState, useEffect, useCallback } from 'react';
import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';
import LandingPage from './components/LandingPage';
import StatCards from './components/StatCards';
import TrafficChart from './components/TrafficChart';
import ThreatDistribution from './components/ThreatDistribution';
import RecentDetections from './components/RecentDetections';
import SystemHealth from './components/SystemHealth';
import LiveMonitoring from './components/LiveMonitoring';
import ThreatsPage from './components/ThreatsPage';
import NetworkGraph from './components/NetworkGraph';
import AttackTimeline from './components/AttackTimeline';
import ReportsPage from './components/ReportsPage';
import MitreAttackView from './components/MitreAttackView';
import ModelRegistryView from './components/ModelRegistryView';
import LogAnalysis from './components/LogAnalysis';
import ExplainabilityPanel from './components/ExplainabilityPanel';
import VulnerableLab from './components/VulnerableLab';
import { ChevronDown } from 'lucide-react';

import {
  fetchDashboard,
  switchSimulation,
  fetchModelStatus
} from './services/api';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [activeTab, setActiveTab] = useState('all');
  const [tabMeta, setTabMeta] = useState(null);
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [scenario, setScenario] = useState('normal');
  const [isSwitching, setIsSwitching] = useState(false);
  const [modelInfo, setModelInfo] = useState(null);

  useEffect(() => {
    fetchModelStatus().then((info) => setModelInfo(info));
  }, []);

  // Reset scroll to top on tab switch
  useEffect(() => {
    const main = document.querySelector('main');
    if (main) main.scrollTop = 0;
  }, [activeTab]);

  const handleSelectScenario = async (newScenario) => {
    if (newScenario === scenario) return;
    setIsSwitching(true);
    setScenario(newScenario);
    try {
      await switchSimulation(newScenario);
    } catch (err) {
      console.error("Failed to switch simulation scenario:", err);
    } finally {
      setIsSwitching(false);
    }
  };

  const handleNavigate = (tab, meta) => {
    if (tab === 'home') {
      setActiveTab('home');
      return;
    }
    setIsAuthenticated(true);
    setActiveTab(tab);
    setTabMeta(meta || null);
  };

  // Render standalone Landing Page if not authenticated or explicitly visiting Home
  if (!isAuthenticated || activeTab === 'home') {
    return (
      <LandingPage
        onEnterApp={() => {
          setIsAuthenticated(true);
          setActiveTab('all');
        }}
      />
    );
  }

  return (
    <div className="flex h-screen bg-[#f8fafc] text-slate-900 overflow-hidden font-sans antialiased">
      {/* 1. Left Sidebar Matching Mockup (Always Dark Navy) */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={handleNavigate}
        isCollapsed={isCollapsed}
        onToggleCollapse={() => setIsCollapsed(!isCollapsed)}
      />

      {/* 2. Main Viewport */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        {/* Top Header Bar Matching Mockups (Pure White) with functional Universal Search */}
        <TopBar
          currentScenario={scenario}
          onSelectScenario={handleSelectScenario}
          isSwitching={isSwitching}
          onLogout={() => {
            setIsAuthenticated(false);
            setActiveTab('home');
          }}
          onNavigate={handleNavigate}
          onToggleSidebar={() => setIsCollapsed(!isCollapsed)}
          isCollapsed={isCollapsed}
        />

        {/* Dynamic Main Content Container */}
        <main className="flex-1 overflow-y-auto bg-[#f8fafc] p-6 sm:p-8 space-y-6">
          
          {/* TAB 1: DASHBOARD (EXACT MOCKUP 2) */}
          {activeTab === 'all' && (
            <div className="space-y-6">
              {/* Dashboard Title Header Matching Mockup 2 */}
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-2xl font-bold text-slate-900 font-sans tracking-tight">
                    Dashboard
                  </h1>
                  <p className="text-xs text-slate-500 mt-1">
                    Real-time network security overview
                  </p>
                </div>

                <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-xs font-medium text-slate-700 hover:bg-slate-50 shadow-xs cursor-pointer">
                  <span>Last 1 Hour</span>
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                </button>
              </div>

              {/* 4 Stat Cards Matching Mockup 2 */}
              <StatCards scenario={scenario} />

              {/* Row 2: Network Traffic (2 cols) | Threat Distribution (1 col) */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2">
                  <TrafficChart />
                </div>
                <div className="lg:col-span-1">
                  <ThreatDistribution />
                </div>
              </div>

              {/* Row 3: Recent Detections (2 cols) | System Health (1 col) */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2">
                  <RecentDetections onViewAll={() => setActiveTab('threats')} />
                </div>
                <div className="lg:col-span-1">
                  <SystemHealth />
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: LIVE MONITORING (EXACT MOCKUP 3) */}
          {activeTab === 'live' && (
            <LiveMonitoring />
          )}

          {/* TAB 3: THREATS (EXACT MOCKUP 4) */}
          {activeTab === 'threats' && (
            <ThreatsPage onSelectTab={setActiveTab} />
          )}

          {/* TAB 4: NETWORK GRAPH (EXACT MOCKUP 5) */}
          {activeTab === 'graph' && (
            <NetworkGraph
              scenario={scenario}
              onSelectScenario={handleSelectScenario}
              onNavigateTab={handleNavigate}
              initialMeta={tabMeta}
            />
          )}

          {/* TAB 5: AI EXPLANATIONS (EXACT MOCKUP 6) */}
          {activeTab === 'explainability' && (
            <ExplainabilityPanel onBackToThreat={() => setActiveTab('threats')} />
          )}

          {/* TAB 6: ATTACK TIMELINE */}
          {activeTab === 'timeline' && (
            <AttackTimeline />
          )}

          {/* TAB 7: LOG ANALYSIS */}
          {activeTab === 'loganalysis' && (
            <div className="space-y-6">
              <LogAnalysis initialMeta={tabMeta} />
            </div>
          )}

          {/* TAB 8: MODEL PERFORMANCE */}
          {activeTab === 'models' && (
            <div className="space-y-6">
              <ModelRegistryView modelInfo={modelInfo} />
            </div>
          )}

          {/* TAB 9: REPORTS */}
          {activeTab === 'reports' && (
            <ReportsPage />
          )}

          {/* TAB 10: MITRE ATT&CK */}
          {activeTab === 'mitre' && (
            <MitreAttackView />
          )}

          {/* TAB 11: VULNERABLE LAB */}
          {activeTab === 'lab' && (
            <VulnerableLab />
          )}

        </main>
      </div>
    </div>
  );
}
