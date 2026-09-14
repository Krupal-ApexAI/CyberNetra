import React, { useState, useEffect, useRef } from 'react';
import {
  Menu,
  Search,
  ChevronDown,
  LogOut,
  SlidersHorizontal,
  Home,
  Activity,
  Layers,
  FileText,
  Share2,
  Loader2
} from 'lucide-react';
import { searchAPI } from '../services/api';

export default function TopBar({
  currentScenario,
  onSelectScenario,
  isSwitching,
  onLogout,
  onNavigate,
  onToggleSidebar,
  isCollapsed
}) {
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [showScenarioMenu, setShowScenarioMenu] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [isSearching, setIsSearching] = useState(false);
  const [showSearchDropdown, setShowSearchDropdown] = useState(false);

  const searchContainerRef = useRef(null);
  const scenarioDropdownRef = useRef(null);

  const scenarios = [
    { id: 'normal', label: 'Normal Traffic (Baseline)' },
    { id: 'suspicious', label: 'Suspicious Port Scan (Reconnaissance)' },
    { id: 'ddos', label: 'Volumetric DDoS Attack (Critical)' },
    { id: 'progression', label: 'Multi-Stage Attack Progression' }
  ];

  // Debounced search query
  useEffect(() => {
    const trimmed = searchQuery.trim();
    if (!trimmed) {
      const resetTimer = setTimeout(() => {
        setSearchResults([]);
        setIsSearching(false);
      }, 0);
      return () => clearTimeout(resetTimer);
    }

    setIsSearching(true);
    const timer = setTimeout(async () => {
      try {
        const data = await searchAPI(trimmed);
        setSearchResults(data.results || []);
        setShowSearchDropdown(true);
      } catch (err) {
        console.error("Search failed:", err);
      } finally {
        setIsSearching(false);
      }
    }, 200);

    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Click outside listener to close search & scenario dropdowns
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (searchContainerRef.current && !searchContainerRef.current.contains(e.target)) {
        setShowSearchDropdown(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSelectResult = (item) => {
    setShowSearchDropdown(false);
    setSearchQuery('');
    if (onNavigate) {
      onNavigate(item.tab || 'all', item.meta);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && searchResults.length > 0) {
      handleSelectResult(searchResults[0]);
    } else if (e.key === 'Escape') {
      setShowSearchDropdown(false);
    }
  };

  const getCategoryIcon = (category) => {
    if (category.includes('IP')) return <Share2 className="w-3.5 h-3.5 text-blue-600" />;
    if (category.includes('Threat')) return <Activity className="w-3.5 h-3.5 text-rose-600" />;
    if (category.includes('MITRE')) return <Layers className="w-3.5 h-3.5 text-purple-600" />;
    if (category.includes('Report')) return <FileText className="w-3.5 h-3.5 text-emerald-600" />;
    return <Search className="w-3.5 h-3.5 text-slate-400" />;
  };

  return (
    <header className="h-16 bg-white border-b border-slate-200 px-6 sm:px-8 flex items-center justify-between gap-4 select-none z-30 shrink-0 shadow-xs">
      {/* Left: Sidebar Toggle Button (Translucent Glass) + Search Bar */}
      <div className="flex items-center gap-3 flex-1 max-w-md">
        {onToggleSidebar && (
          <button
            type="button"
            onClick={onToggleSidebar}
            className="p-2 rounded-lg bg-slate-100/70 hover:bg-slate-200/80 border border-slate-200/80 text-slate-600 hover:text-slate-900 transition-all cursor-pointer backdrop-blur-sm shadow-xs flex items-center justify-center shrink-0 hover:border-slate-300"
            title={isCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
            aria-label="Toggle Sidebar"
          >
            <Menu className="w-4 h-4" />
          </button>
        )}

        {/* Search Bar with Live Universal Dropdown */}
        <div ref={searchContainerRef} className="flex-1 relative">
        <div className="relative w-full">
          {isSearching ? (
            <Loader2 className="w-4 h-4 text-blue-600 absolute left-3.5 top-1/2 -translate-y-1/2 animate-spin" />
          ) : (
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          )}
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setShowSearchDropdown(true);
            }}
            onFocus={() => {
              if (searchQuery.trim() && searchResults.length > 0) {
                setShowSearchDropdown(true);
              }
            }}
            onKeyDown={handleKeyDown}
            placeholder="Search IP address, domain, or attack type..."
            className="w-full bg-slate-50 hover:bg-slate-100/80 focus:bg-white border border-slate-200 focus:border-blue-500 rounded-lg pl-10 pr-8 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/10 transition-all font-sans"
          />
          {searchQuery && (
            <button
              onClick={() => {
                setSearchQuery('');
                setShowSearchDropdown(false);
              }}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400 hover:text-slate-600 cursor-pointer"
            >
              ✕
            </button>
          )}
        </div>

        {/* Live Search Results Dropdown */}
        {showSearchDropdown && searchQuery.trim() && (
          <div className="absolute left-0 right-0 mt-2 bg-white rounded-xl border border-slate-200 shadow-2xl overflow-hidden z-50 animate-in fade-in duration-150">
            <div className="p-2 border-b border-slate-100 bg-slate-50 flex items-center justify-between text-[11px] text-slate-500">
              <span className="font-semibold uppercase tracking-wider text-[10px]">
                {searchResults.length > 0 ? `Results for "${searchQuery}"` : 'No direct matches'}
              </span>
              <span className="text-[10px] font-mono">Press Enter to Jump</span>
            </div>

            {searchResults.length > 0 ? (
              <div className="max-h-72 overflow-y-auto divide-y divide-slate-100 custom-scrollbar">
                {searchResults.map((item, idx) => (
                  <div
                    key={idx}
                    onClick={() => handleSelectResult(item)}
                    className="p-3 hover:bg-slate-50 cursor-pointer transition-colors flex items-start gap-3 group"
                  >
                    <div className="p-2 rounded-lg bg-slate-100 group-hover:bg-white group-hover:shadow-xs transition-all mt-0.5">
                      {getCategoryIcon(item.category)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold text-slate-900 truncate group-hover:text-blue-600 transition-colors">
                          {item.title}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 group-hover:bg-blue-50 group-hover:text-blue-700">
                          {item.tab.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500 truncate mt-0.5">
                        {item.subtitle}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-6 text-center text-xs text-slate-500">
                No matching network nodes, attacks, or forensic artifacts found for <strong className="text-slate-800">"{searchQuery}"</strong>.
              </div>
            )}
          </div>
        )}
      </div>
    </div>

      {/* Right Controls: Scenario Switcher + System Online + Avatar */}
      <div className="flex items-center gap-5 shrink-0">
        {/* Scenario Quick Selector */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setShowScenarioMenu(!showScenarioMenu)}
            disabled={isSwitching}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 hover:border-slate-300 text-xs font-medium text-slate-700 transition-all cursor-pointer shadow-2xs"
          >
            <SlidersHorizontal className="w-3.5 h-3.5 text-blue-600" />
            <span className="text-slate-500">Scenario:</span>
            <span className="font-semibold capitalize text-slate-900">
              {currentScenario}
            </span>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          </button>

          {showScenarioMenu && (
            <div className="absolute right-0 mt-2 w-56 rounded-xl bg-white border border-slate-200 shadow-xl p-1.5 z-50 animate-in fade-in duration-150">
              <div className="px-3 py-1.5 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Simulated Scenarios
              </div>
              {scenarios.map((sc) => (
                <button
                  key={sc.id}
                  onClick={() => {
                    onSelectScenario(sc.id);
                    setShowScenarioMenu(false);
                  }}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs transition-colors text-left cursor-pointer ${
                    currentScenario === sc.id
                      ? 'bg-blue-50 text-blue-700 font-semibold'
                      : 'text-slate-700 hover:bg-slate-50'
                  }`}
                >
                  <span>{sc.label}</span>
                  {currentScenario === sc.id && (
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-600" />
                  )}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* System Online Badge (Matching Mockup) */}
        <div className="flex items-center gap-2 text-xs font-medium text-slate-700">
          <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-xs animate-pulse" />
          <span>System Online</span>
        </div>

        {/* User Profile Avatar "KA" (Krupal Ameti) */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setShowProfileMenu(!showProfileMenu)}
            className="flex items-center gap-2.5 pl-1 pr-2 py-1 rounded-full hover:bg-slate-100 transition-all cursor-pointer"
          >
            <div className="w-8 h-8 rounded-full bg-[#0c1322] flex items-center justify-center font-bold text-xs text-white shadow-xs">
              KA
            </div>
            <span className="text-xs font-semibold text-slate-800 font-sans hidden sm:inline">
              Krupal Ameti
            </span>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          </button>

          {showProfileMenu && (
            <div className="absolute right-0 mt-2 w-52 rounded-xl bg-white border border-slate-200 shadow-xl p-1.5 z-50 animate-in fade-in duration-150">
              <div className="px-3 py-2 border-b border-slate-100">
                <div className="text-xs font-bold text-slate-900">Krupal Ameti</div>
                <div className="text-[11px] text-slate-500 truncate">Lead Security Researcher</div>
              </div>

              <div className="py-1">
                <button
                  onClick={() => {
                    setShowProfileMenu(false);
                    if (onNavigate) onNavigate('home');
                  }}
                  className="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-slate-700 hover:bg-slate-50 rounded-lg text-left cursor-pointer"
                >
                  <Home className="w-3.5 h-3.5 text-blue-600" />
                  <span>Landing Page (Home)</span>
                </button>

                <button
                  onClick={() => {
                    setShowProfileMenu(false);
                    if (onLogout) onLogout();
                  }}
                  className="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-rose-600 hover:bg-rose-50 rounded-lg text-left cursor-pointer font-medium"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>Sign Out</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
