import React, { useState, useEffect, useCallback } from 'react';
import Sidebar from './components/Sidebar';
import SimulationControls from './components/SimulationControls';
import StatCards from './components/StatCards';
import TrafficChart from './components/TrafficChart';
import RiskScore from './components/RiskScore';
import AttackForecast from './components/AttackForecast';
import ExplainabilityPanel from './components/ExplainabilityPanel';
import Alerts from './components/Alerts';
import ModelRegistryView from './components/ModelRegistryView';

import {
  fetchDashboard,
  fetchTraffic,
  fetchForecast,
  fetchExplainability,
  fetchAlerts,
  switchSimulation,
  fetchModelStatus
} from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('all');
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [scenario, setScenario] = useState('normal');
  const [isSwitching, setIsSwitching] = useState(false);

  // Data States
  const [dashboardStats, setDashboardStats] = useState(null);
  const [trafficData, setTrafficData] = useState([]);
  const [forecastData, setForecastData] = useState(null);
  const [explainabilityData, setExplainabilityData] = useState(null);
  const [alertsData, setAlertsData] = useState([]);
  const [modelInfo, setModelInfo] = useState(null);

  // Centralized data fetcher
  const loadDashboardData = useCallback(async (activeScenario = scenario) => {
    try {
      const [dashRes, trafRes, foreRes, expRes, alertRes] = await Promise.all([
        fetchDashboard(activeScenario),
        fetchTraffic(activeScenario),
        fetchForecast(activeScenario),
        fetchExplainability(activeScenario),
        fetchAlerts(activeScenario)
      ]);

      setDashboardStats(dashRes.data);
      setTrafficData(trafRes.data || []);
      setForecastData(foreRes.data);
      setExplainabilityData(expRes.data);
      setAlertsData(alertRes.data || []);

      if (dashRes.data?.scenario) {
        setScenario(dashRes.data.scenario);
      }
    } catch (err) {
      console.error("Error loading dashboard data:", err);
    }
  }, [scenario]);

  // Initial load & model status
  useEffect(() => {
    loadDashboardData('normal');
    fetchModelStatus().then((info) => setModelInfo(info));

    const timer = setInterval(() => {
      loadDashboardData(scenario);
    }, 5000);

    return () => clearInterval(timer);
  }, [loadDashboardData, scenario]);

  // Scenario switch handler
  const handleSelectScenario = async (newScenario) => {
    if (newScenario === scenario) return;
    setIsSwitching(true);
    setScenario(newScenario);

    try {
      await switchSimulation(newScenario);
      await loadDashboardData(newScenario);
    } catch (err) {
      console.error("Failed to switch simulation scenario:", err);
    } finally {
      setIsSwitching(false);
    }
  };

  return (
    <div className="flex h-screen bg-[#070b12] text-slate-100 overflow-hidden font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* 1. Left Collapsible Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        isCollapsed={isCollapsed}
        onToggleCollapse={() => setIsCollapsed(!isCollapsed)}
        scenario={scenario}
        alertCount={alertsData?.length || 0}
      />

      {/* 2. Main Application Body - Zero Clutter, Clean Viewport */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        {/* Dynamic Main Workspace Viewport */}
        <main className="flex-1 overflow-y-auto px-4 sm:px-8 py-6 space-y-6 custom-scrollbar bg-gradient-to-b from-[#070b12] to-[#090d18]">
          {/* TAB 1: ALL / UNIFIED OPERATIONS CENTER */}
          {activeTab === 'all' && (
            <div className="space-y-6">
              {/* Simulation Scenario Switcher Cards */}
              <section>
                <SimulationControls
                  currentScenario={scenario}
                  onSelectScenario={handleSelectScenario}
                  isSwitching={isSwitching}
                />
              </section>

              {/* 4 KPI Metric Cards */}
              <section>
                <StatCards stats={dashboardStats} scenario={scenario} />
              </section>

              {/* Traffic Timeline & Risk Gauge Side-by-Side */}
              <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2">
                  <TrafficChart data={trafficData} scenario={scenario} />
                </div>
                <div className="lg:col-span-1">
                  <RiskScore
                    score={
                      dashboardStats?.risk_score ??
                      (scenario === 'ddos' ? 97 : scenario === 'progression' ? 82 : scenario === 'suspicious' ? 48 : 12)
                    }
                    level={
                      dashboardStats?.risk_level ??
                      (scenario === 'ddos' ? 'CRITICAL' : scenario === 'progression' ? 'HIGH' : scenario === 'suspicious' ? 'MEDIUM' : 'LOW')
                    }
                    confidence={forecastData?.confidence ?? 95}
                  />
                </div>
              </section>

              {/* Attack Forecaster Component */}
              <section>
                <AttackForecast forecast={forecastData} scenario={scenario} />
              </section>

              {/* Explainable AI Forensic Attribution Panel */}
              <section>
                <ExplainabilityPanel data={explainabilityData} />
              </section>

              {/* Real-Time SOC Incident Alerts */}
              <section>
                <Alerts alerts={alertsData} />
              </section>
            </div>
          )}

          {/* TAB 2: ATTACK STAGE FORECASTER */}
          {activeTab === 'forecast' && (
            <div className="space-y-6">
              <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2">
                  <AttackForecast forecast={forecastData} scenario={scenario} />
                </div>
                <div className="lg:col-span-1">
                  <RiskScore
                    score={dashboardStats?.risk_score ?? 12}
                    level={dashboardStats?.risk_level ?? 'LOW'}
                    confidence={forecastData?.confidence ?? 95}
                  />
                </div>
              </section>

              <section>
                <StatCards stats={dashboardStats} scenario={scenario} />
              </section>
            </div>
          )}

          {/* TAB 3: EXPLAINABLE AI (XAI) */}
          {activeTab === 'explainability' && (
            <div className="space-y-6">
              <ExplainabilityPanel data={explainabilityData} />
            </div>
          )}

          {/* TAB 4: TRAFFIC TELEMETRY */}
          {activeTab === 'traffic' && (
            <div className="space-y-6">
              <TrafficChart data={trafficData} scenario={scenario} />
              <StatCards stats={dashboardStats} scenario={scenario} />
            </div>
          )}

          {/* TAB 5: ALERTS & INCIDENTS */}
          {activeTab === 'alerts' && (
            <div className="space-y-6">
              <Alerts alerts={alertsData} />
            </div>
          )}

          {/* TAB 6: MODEL REGISTRY */}
          {activeTab === 'models' && (
            <div className="space-y-6">
              <ModelRegistryView modelInfo={modelInfo} />
            </div>
          )}

          {/* Footer */}
          <footer className="pt-6 pb-2 border-t border-slate-800/60 text-xs text-slate-400 flex flex-col sm:flex-row items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-slate-300">Cyber Netra</span>
              <span>•</span>
              <span>National Technical Research Organisation (NTRO) SIH26153 Prototype</span>
            </div>
            <div className="flex items-center gap-4 font-mono text-[11px]">
              <span className="text-emerald-400">? REST API Active</span>
              <span>FastAPI: http://localhost:8000</span>
            </div>
          </footer>
        </main>
      </div>
    </div>
  );
}
