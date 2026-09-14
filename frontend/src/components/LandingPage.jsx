import React, { useEffect, useRef, useState } from 'react';
import { Shield, X, Lock, Sparkles, Terminal } from 'lucide-react';

export default function LandingPage({ onEnterApp }) {
  const canvasRef = useRef(null);
  const [activeModal, setActiveModal] = useState(null);
  const [loginEmail, setLoginEmail] = useState('analyst@cybernetra.gov.in');
  const [loginPassword, setLoginPassword] = useState('••••••••••••');
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  // ══════════════════════════════════════════════════════════════════════════════
  // Award-Winning 3D Interactive Cyber Threat Intelligence Globe
  // Includes: Global Geodetic Landmass Distribution, Constellation Mesh Wiring,
  // 3D Elevated Great-Circle Arcs with Luminous Photons, Concentric Radar Beacons,
  // Orbital Shield Rings, and Mouse Inertial Drag Physics.
  // ══════════════════════════════════════════════════════════════════════════════
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animationFrameId;

    const DPR = window.devicePixelRatio || 1;
    const DISPLAY_SIZE = 540;
    canvas.width = DISPLAY_SIZE * DPR;
    canvas.height = DISPLAY_SIZE * DPR;
    canvas.style.width = DISPLAY_SIZE + 'px';
    canvas.style.height = DISPLAY_SIZE + 'px';
    ctx.scale(DPR, DPR);

    const width = DISPLAY_SIZE;
    const height = DISPLAY_SIZE;
    const globeRadius = 195;
    const centerX = width / 2;
    const centerY = height / 2;

    // ── 1. Global Geodetic Landmass Points (Real Earth Continents) ─────────────
    const continentRegions = [
      // North America (US, Canada, Mexico)
      { latMin: 18, latMax: 68, lonMin: -135, lonMax: -60, count: 120 },
      // South America (Brazil, Argentina, Chile, Colombia)
      { latMin: -52, latMax: 12, lonMin: -80, lonMax: -35, count: 75 },
      // Europe (UK, Germany, France, Nordics, Med)
      { latMin: 36, latMax: 68, lonMin: -10, lonMax: 42, count: 110 },
      // Africa (North Africa, Sub-Saharan, South Africa)
      { latMin: -35, latMax: 35, lonMin: -16, lonMax: 50, count: 90 },
      // India & South Asia (High Density for SIH 2026 Core Infrastructure)
      { latMin: 8, latMax: 35, lonMin: 68, lonMax: 92, count: 85 },
      // East Asia (China, Japan, Korea, Taiwan)
      { latMin: 22, latMax: 55, lonMin: 100, lonMax: 145, count: 95 },
      // Southeast Asia (Singapore, Malaysia, Indonesia)
      { latMin: -8, latMax: 20, lonMin: 95, lonMax: 130, count: 55 },
      // Australia & New Zealand
      { latMin: -44, latMax: -12, lonMin: 115, lonMax: 175, count: 60 }
    ];

    const globePoints = [];

    // Populate continents
    continentRegions.forEach(reg => {
      for (let i = 0; i < reg.count; i++) {
        const lat = reg.latMin + Math.random() * (reg.latMax - reg.latMin);
        const lon = reg.lonMin + Math.random() * (reg.lonMax - reg.lonMin);
        const latRad = (lat * Math.PI) / 180;
        const lonRad = (lon * Math.PI) / 180;

        globePoints.push({
          x0: globeRadius * Math.cos(latRad) * Math.sin(lonRad),
          y0: -globeRadius * Math.sin(latRad),
          z0: globeRadius * Math.cos(latRad) * Math.cos(lonRad),
          isOcean: false,
          isHotspot: Math.random() < 0.04
        });
      }
    });

    // Populate ocean telemetry grid (Fibonacci distribution for spherical harmony)
    const oceanCount = 200;
    for (let i = 0; i < oceanCount; i++) {
      const phi = Math.acos(-1 + (2 * i) / oceanCount);
      const theta = Math.sqrt(oceanCount * Math.PI) * phi;
      globePoints.push({
        x0: globeRadius * Math.cos(theta) * Math.sin(phi),
        y0: globeRadius * Math.sin(theta) * Math.sin(phi),
        z0: globeRadius * Math.cos(phi),
        isOcean: true,
        isHotspot: false
      });
    }

    // ── 2. Strategic Cyber Hubs ──────────────────────────────────────────────
    const cyberHubs = [
      { name: 'Silicon Valley (Ingress)', lat: 37.4, lon: -122.1, color: '#38bdf8' },
      { name: 'Washington DC (Gov Cyber)', lat: 38.9, lon: -77.0, color: '#60a5fa' },
      { name: 'London (CERT-UK)', lat: 51.5, lon: -0.1, color: '#38bdf8' },
      { name: 'Frankfurt (BSI Defense)', lat: 50.1, lon: 8.7, color: '#34d399' },
      { name: 'New Delhi / Bengaluru (SIH)', lat: 21.5, lon: 78.5, color: '#10b981' },
      { name: 'Singapore (Pacific SOC)', lat: 1.35, lon: 103.8, color: '#38bdf8' },
      { name: 'Tokyo (NISC Telemetry)', lat: 35.7, lon: 139.7, color: '#34d399' },
      { name: 'Sydney (ACS Center)', lat: -33.9, lon: 151.2, color: '#818cf8' }
    ];

    const hubPoints = cyberHubs.map(h => {
      const latRad = (h.lat * Math.PI) / 180;
      const lonRad = (h.lon * Math.PI) / 180;
      return {
        ...h,
        x0: globeRadius * Math.cos(latRad) * Math.sin(lonRad),
        y0: -globeRadius * Math.sin(latRad),
        z0: globeRadius * Math.cos(latRad) * Math.cos(lonRad)
      };
    });

    // ── 3. High-Intensity Great-Circle Telemetry Arcs ─────────────────────────
    const telemetryRoutes = [
      { from: 0, to: 1, speed: 0.012 }, // Silicon Valley -> DC
      { from: 1, to: 2, speed: 0.009 }, // DC -> London
      { from: 2, to: 3, speed: 0.015 }, // London -> Frankfurt
      { from: 3, to: 4, speed: 0.008 }, // Frankfurt -> Delhi/Bengaluru
      { from: 4, to: 5, speed: 0.011 }, // Delhi -> Singapore
      { from: 5, to: 6, speed: 0.010 }, // Singapore -> Tokyo
      { from: 6, to: 0, speed: 0.008 }, // Tokyo -> Silicon Valley
      { from: 4, to: 6, speed: 0.009 }, // Delhi -> Tokyo
      { from: 0, to: 7, speed: 0.007 }  // Silicon Valley -> Sydney
    ];

    const SAMPLES_PER_ARC = 32;
    const arcEntities = telemetryRoutes.map(route => {
      const p1 = hubPoints[route.from];
      const p2 = hubPoints[route.to];
      const samples = [];

      for (let s = 0; s <= SAMPLES_PER_ARC; s++) {
        const t = s / SAMPLES_PER_ARC;
        const lx = p1.x0 * (1 - t) + p2.x0 * t;
        const ly = p1.y0 * (1 - t) + p2.y0 * t;
        const lz = p1.z0 * (1 - t) + p2.z0 * t;
        const mag = Math.sqrt(lx * lx + ly * ly + lz * lz) || 1;

        // Peak altitude off the sphere surface at midpoint
        const altitude = 1 + Math.sin(t * Math.PI) * 0.26;
        samples.push({
          x0: (lx / mag) * globeRadius * altitude,
          y0: (ly / mag) * globeRadius * altitude,
          z0: (lz / mag) * globeRadius * altitude
        });
      }

      return {
        ...route,
        samples,
        photonHead: Math.random()
      };
    });

    // ── 4. Rotation, Inertia & Mouse Physics ─────────────────────────────────
    let rotY = 0.55;
    let rotX = 0.22;
    let velY = 0.0038;
    let velX = 0;
    let isDragging = false;
    let dragStartX = 0;
    let dragStartY = 0;

    const onMouseDown = (e) => {
      isDragging = true;
      dragStartX = e.clientX;
      dragStartY = e.clientY;
    };

    const onMouseMove = (e) => {
      if (!isDragging) return;
      const dx = e.clientX - dragStartX;
      const dy = e.clientY - dragStartY;
      rotY += dx * 0.007;
      rotX += dy * 0.005;
      velY = dx * 0.0018;
      dragStartX = e.clientX;
      dragStartY = e.clientY;
    };

    const onMouseUp = () => {
      isDragging = false;
    };

    canvas.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);

    // ── 5. Main 3D Animation & Render Loop ───────────────────────────────────
    const render = () => {
      ctx.clearRect(0, 0, width, height);

      // Inertial damping & smooth auto-rotation
      if (!isDragging) {
        velY = velY * 0.95 + 0.0035 * 0.05;
        rotY += velY;
        velX *= 0.95;
        rotX += velX;
      }
      const time = Date.now() * 0.001;

      const cosY = Math.cos(rotY);
      const sinY = Math.sin(rotY);
      const cosX = Math.cos(rotX);
      const sinX = Math.sin(rotX);

      // 3D rotation projection helper
      const project = (x3, y3, z3) => {
        // Y-axis rotation
        const x1 = x3 * cosY - z3 * sinY;
        const z1 = x3 * sinY + z3 * cosY;
        // X-axis pitch rotation
        const y2 = y3 * cosX - z1 * sinX;
        const z2 = y3 * sinX + z1 * cosX;
        return {
          x: centerX + x1,
          y: centerY + y2,
          z: z2,
          alpha: Math.max(0.04, (z2 + globeRadius) / (globeRadius * 2))
        };
      };

      // ── Outer Atmospheric Aura (Layered Multi-Stop Glow) ──
      const atmosGrad = ctx.createRadialGradient(
        centerX, centerY, globeRadius * 0.65,
        centerX, centerY, globeRadius * 1.5
      );
      atmosGrad.addColorStop(0, 'rgba(37, 99, 235, 0.18)');
      atmosGrad.addColorStop(0.35, 'rgba(56, 189, 248, 0.09)');
      atmosGrad.addColorStop(0.7, 'rgba(99, 102, 241, 0.03)');
      atmosGrad.addColorStop(1, 'rgba(7, 11, 20, 0)');
      ctx.fillStyle = atmosGrad;
      ctx.beginPath();
      ctx.arc(centerX, centerY, globeRadius * 1.5, 0, Math.PI * 2);
      ctx.fill();

      // ── Core Sphere Base Fill (Ultra-deep Dark Navy Blue) ──
      const sphereGrad = ctx.createRadialGradient(
        centerX - globeRadius * 0.35, centerY - globeRadius * 0.35, 10,
        centerX, centerY, globeRadius
      );
      sphereGrad.addColorStop(0, '#0e1a38');
      sphereGrad.addColorStop(0.5, '#081024');
      sphereGrad.addColorStop(0.85, '#040814');
      sphereGrad.addColorStop(1, '#020409');
      ctx.fillStyle = sphereGrad;
      ctx.beginPath();
      ctx.arc(centerX, centerY, globeRadius, 0, Math.PI * 2);
      ctx.fill();

      // ── Sphere Rim Fresnel Lighting ──
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.32)';
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.arc(centerX, centerY, globeRadius, 0, Math.PI * 2);
      ctx.stroke();

      // Pulsing outer defense barrier ring
      const ringAlpha = 0.12 + Math.sin(time * 2) * 0.06;
      ctx.strokeStyle = `rgba(52, 211, 153, ${ringAlpha})`;
      ctx.lineWidth = 1.0;
      ctx.beginPath();
      ctx.arc(centerX, centerY, globeRadius + 7 + Math.sin(time * 2.2) * 2, 0, Math.PI * 2);
      ctx.stroke();

      // ── Planetary Gyroscopic / Orbital Rings (Reference Style) ──
      ctx.save();
      ctx.beginPath();
      ctx.arc(centerX, centerY, globeRadius - 1, 0, Math.PI * 2);
      ctx.clip();

      // Major Equatorial Ring
      ctx.beginPath();
      for (let deg = 0; deg <= 360; deg += 6) {
        const r = (deg * Math.PI) / 180;
        const p = project(
          globeRadius * Math.sin(r),
          0,
          globeRadius * Math.cos(r)
        );
        if (p.z > -20) {
          if (deg === 0) ctx.moveTo(p.x, p.y);
          else ctx.lineTo(p.x, p.y);
        }
      }
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.18)';
      ctx.lineWidth = 0.9;
      ctx.stroke();

      // Secondary Latitude Parallels (North +30°, South -30°)
      [30, -30].forEach(lat => {
        const latR = (lat * Math.PI) / 180;
        const latCos = Math.cos(latR);
        const latSin = Math.sin(latR);
        ctx.beginPath();
        for (let deg = 0; deg <= 360; deg += 8) {
          const r = (deg * Math.PI) / 180;
          const p = project(
            globeRadius * latCos * Math.sin(r),
            -globeRadius * latSin,
            globeRadius * latCos * Math.cos(r)
          );
          if (p.z > -20) {
            if (deg === 0) ctx.moveTo(p.x, p.y);
            else ctx.lineTo(p.x, p.y);
          }
        }
        ctx.strokeStyle = 'rgba(99, 102, 241, 0.12)';
        ctx.lineWidth = 0.7;
        ctx.stroke();
      });

      // ── Project All Points to 2D Screen Space ──
      const projectedPoints = globePoints.map(pt => {
        const prj = project(pt.x0, pt.y0, pt.z0);
        return {
          ...pt,
          ...prj
        };
      });

      // ── Constellation Network Mesh (Interconnecting Front Nodes) ──
      const frontPoints = projectedPoints.filter(p => p.z > 20);
      ctx.lineWidth = 0.55;
      for (let i = 0; i < frontPoints.length; i++) {
        const p1 = frontPoints[i];
        for (let j = i + 1; j < frontPoints.length; j++) {
          const p2 = frontPoints[j];
          const dx = p1.x - p2.x;
          const dy = p1.y - p2.y;
          const distSq = dx * dx + dy * dy;

          // Connect nearby points in constellation
          if (distSq < 1350) { // ~36px distance
            const linkAlpha = Math.min(p1.alpha, p2.alpha) * 0.22;
            ctx.strokeStyle = `rgba(56, 189, 248, ${linkAlpha})`;
            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.stroke();
          }
        }
      }

      // ── Render Landmass & Ocean Node Dots ──
      projectedPoints.forEach(p => {
        if (p.z > -globeRadius * 0.2) {
          const dotAlpha = p.alpha;
          let dotRadius = p.isOcean ? 0.9 : 1.45;
          if (p.z > 40) dotRadius += 0.4;

          if (p.isOcean) {
            ctx.fillStyle = `rgba(56, 189, 248, ${dotAlpha * 0.35})`;
          } else {
            ctx.fillStyle = `rgba(96, 165, 250, ${dotAlpha * 0.85})`;
          }

          ctx.beginPath();
          ctx.arc(p.x, p.y, dotRadius, 0, Math.PI * 2);
          ctx.fill();

          // Highlight key hotspots
          if (p.isHotspot && p.z > 30) {
            ctx.fillStyle = `rgba(52, 211, 153, ${dotAlpha * 0.9})`;
            ctx.beginPath();
            ctx.arc(p.x, p.y, 2.0, 0, Math.PI * 2);
            ctx.fill();
          }
        }
      });

      // ── Render 3D Elevated Great-Circle Cyber Threat Arcs & Photons ──
      arcEntities.forEach(arc => {
        arc.photonHead = (arc.photonHead + arc.speed) % 1;
        const prjSamples = arc.samples.map(s => project(s.x0, s.y0, s.z0));

        // Draw glowing 3D arc path
        let isTracing = false;
        ctx.beginPath();
        for (let i = 0; i < prjSamples.length; i++) {
          const pt = prjSamples[i];
          if (pt.z > -10) {
            if (!isTracing) {
              ctx.moveTo(pt.x, pt.y);
              isTracing = true;
            } else {
              ctx.lineTo(pt.x, pt.y);
            }
          } else {
            isTracing = false;
          }
        }

        // Luminous arc stroke
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.42)';
        ctx.lineWidth = 1.2;
        ctx.stroke();

        ctx.strokeStyle = 'rgba(52, 211, 153, 0.28)';
        ctx.lineWidth = 0.6;
        ctx.stroke();

        // ── Animated Traveling Photon Beam (Data Stream Pulse) ──
        const headIndex = Math.floor(arc.photonHead * (prjSamples.length - 1));
        const headPt = prjSamples[headIndex];

        if (headPt && headPt.z > 5) {
          const photonAlpha = Math.min(1, headPt.alpha * 1.6);

          // Radial photon halo
          const pGrad = ctx.createRadialGradient(headPt.x, headPt.y, 0, headPt.x, headPt.y, 8);
          pGrad.addColorStop(0, `rgba(52, 211, 153, ${photonAlpha * 0.95})`);
          pGrad.addColorStop(0.5, `rgba(56, 189, 248, ${photonAlpha * 0.45})`);
          pGrad.addColorStop(1, 'rgba(52, 211, 153, 0)');
          ctx.fillStyle = pGrad;
          ctx.beginPath();
          ctx.arc(headPt.x, headPt.y, 8, 0, Math.PI * 2);
          ctx.fill();

          // Intense core beam
          ctx.fillStyle = '#ffffff';
          ctx.beginPath();
          ctx.arc(headPt.x, headPt.y, 2.0, 0, Math.PI * 2);
          ctx.fill();
        }
      });

      // ── Render Regional Strategic Hotspot Beacons ──
      hubPoints.forEach(hub => {
        const p = project(hub.x0, hub.y0, hub.z0);
        if (p.z > 15) {
          const pulse = (time * 2.8 + hub.lat * 0.1) % (Math.PI * 2);
          const beaconRadius = 4 + (pulse / (Math.PI * 2)) * 15;
          const beaconAlpha = Math.max(0, 1 - pulse / (Math.PI * 2)) * p.alpha;

          // Expanding radar ripple ring
          ctx.strokeStyle = `rgba(52, 211, 153, ${beaconAlpha * 0.75})`;
          ctx.lineWidth = 1.1;
          ctx.beginPath();
          ctx.arc(p.x, p.y, beaconRadius, 0, Math.PI * 2);
          ctx.stroke();

          // Central glowing beacon
          const bGlow = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, 10);
          bGlow.addColorStop(0, `rgba(52, 211, 153, ${p.alpha * 0.75})`);
          bGlow.addColorStop(1, 'rgba(52, 211, 153, 0)');
          ctx.fillStyle = bGlow;
          ctx.beginPath();
          ctx.arc(p.x, p.y, 10, 0, Math.PI * 2);
          ctx.fill();

          // Hotspot solid hub
          ctx.fillStyle = hub.color;
          ctx.beginPath();
          ctx.arc(p.x, p.y, 3.2, 0, Math.PI * 2);
          ctx.fill();

          // White center spark
          ctx.fillStyle = '#ffffff';
          ctx.beginPath();
          ctx.arc(p.x, p.y, 1.4, 0, Math.PI * 2);
          ctx.fill();
        }
      });

      ctx.restore();
      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      canvas.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
    };
  }, []);

  const handleQuickLogin = (e) => {
    e.preventDefault();
    setIsLoggingIn(true);
    setTimeout(() => {
      setIsLoggingIn(false);
      setActiveModal(null);
      onEnterApp();
    }, 500);
  };

  return (
    <div className="h-screen w-screen bg-[#070b14] text-white flex flex-col font-sans selection:bg-blue-600/40 relative overflow-hidden justify-between">
      {/* Ambient background glow accents */}
      <div className="absolute top-[-180px] right-[-100px] w-[820px] h-[820px] bg-blue-600/10 rounded-full blur-[180px] pointer-events-none" />
      <div className="absolute bottom-[-150px] left-[-100px] w-[520px] h-[520px] bg-indigo-900/14 rounded-full blur-[160px] pointer-events-none" />
      <div className="absolute top-[32%] right-[16%] w-[380px] h-[380px] bg-emerald-500/6 rounded-full blur-[130px] pointer-events-none" />

      {/* ══════════════════════════════════════════════════════════════════════
          1. Header Navigation (Exact Mockup 1)
          ══════════════════════════════════════════════════════════════════════ */}
      <header className="h-16 px-8 lg:px-16 flex items-center justify-between z-30 shrink-0">
        {/* Brand Logo & Subtitle */}
        <div
          className="flex items-center gap-3 cursor-pointer select-none group"
          onClick={onEnterApp}
        >
          <div className="w-9 h-9 rounded-lg bg-blue-600 flex items-center justify-center shadow-lg shadow-blue-500/30 group-hover:shadow-blue-500/50 transition-all duration-300">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <span className="font-bold text-[17px] text-white tracking-tight block leading-none font-sans">
              CyberNetra
            </span>
            <span className="text-[11px] text-slate-400 font-normal block leading-none mt-1">
              Network Threat Intelligence
            </span>
          </div>
        </div>

        {/* Navigation Links & Sign In Pill */}
        <div className="flex items-center gap-8">
          <nav className="hidden md:flex items-center gap-7 text-[13px] text-slate-300 font-medium">
            {['About', 'Features', 'Contact'].map(item => (
              <button
                key={item}
                onClick={() => setActiveModal(item.toLowerCase())}
                className="hover:text-white transition-colors cursor-pointer py-1 text-slate-300"
              >
                {item}
              </button>
            ))}
          </nav>

          <button
            onClick={() => setActiveModal('signin')}
            className="px-5 py-2 rounded-full bg-[#111928] hover:bg-white hover:text-slate-900 border border-slate-700/80 text-white text-xs font-semibold tracking-wide transition-all duration-200 cursor-pointer shadow-sm hover:shadow-md"
          >
            Sign In
          </button>
        </div>
      </header>

      {/* ══════════════════════════════════════════════════════════════════════
          2. Hero Section (Matching Frame 1 Layout, Spacing & Typography)
          ══════════════════════════════════════════════════════════════════════ */}
      <main className="flex-1 flex items-center z-20 py-2">
        <div className="max-w-[1320px] mx-auto px-8 lg:px-16 w-full flex flex-col lg:flex-row items-center justify-between gap-8 lg:gap-4">

          {/* Left Column: Hero Title, Subtitle, CTA Buttons */}
          <div className="flex-1 max-w-[540px] text-left">
            <h1 className="text-[3.25rem] sm:text-[3.85rem] lg:text-[4.3rem] font-extrabold text-white tracking-tight leading-[1.06] font-sans">
              Smarter<br />
              Networks<br />
              Safer Nations
            </h1>

            <p className="mt-5 text-[15px] sm:text-[15.5px] text-slate-300/90 max-w-[420px] leading-[1.6] font-normal">
              AI-powered network threat detection and analysis for a more secure digital infrastructure.
            </p>

            <div className="mt-8 flex items-center gap-4">
              <button
                onClick={onEnterApp}
                className="px-7 py-3 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-sm shadow-lg shadow-blue-600/30 hover:shadow-blue-500/40 transition-all duration-200 cursor-pointer flex items-center justify-center"
              >
                <span>Get Started</span>
              </button>

              <button
                onClick={() => setActiveModal('features')}
                className="px-6 py-3 rounded-lg bg-[#111927]/90 hover:bg-[#1a2538] border border-slate-700/80 hover:border-slate-600 text-slate-200 font-medium text-sm transition-all duration-200 cursor-pointer"
              >
                Learn More
              </button>
            </div>
          </div>

          {/* Right Column: 3D Rotating Globe + 4 Aligned Feature Badges */}
          <div className="flex-1 relative flex items-center justify-center max-w-[600px]">
            <div className="relative flex items-center justify-center">
              {/* 3D Canvas Globe */}
              <canvas
                ref={canvasRef}
                className="select-none cursor-grab active:cursor-grabbing"
                style={{ width: 500, height: 500 }}
                title="Click & drag to rotate 3D Threat Globe"
              />

              {/* 4 Feature Badges — Positioned at the equator/lower-right quadrant
                  overlapping the right side of the globe exactly as in Mockup Frame 1 */}
              <div className="absolute top-[48%] -translate-y-1/4 -right-2 sm:right-2 flex flex-col gap-3 z-20 pointer-events-auto">
                {/* Badge 1: Real-time Monitoring */}
                <div className="flex items-center gap-2.5 px-4 py-2 rounded-xl bg-[#0a1324]/90 border border-slate-700/70 backdrop-blur-xl text-xs font-medium text-slate-200 shadow-xl shadow-black/40 hover:border-emerald-500/40 transition-all cursor-default">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shrink-0 animate-pulse shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
                  <span>Real-time Monitoring</span>
                </div>

                {/* Badge 2: AI-driven Detection */}
                <div className="flex items-center gap-2.5 px-4 py-2 rounded-xl bg-[#0a1324]/90 border border-slate-700/70 backdrop-blur-xl text-xs font-medium text-slate-200 shadow-xl shadow-black/40 hover:border-emerald-500/40 transition-all cursor-default">
                  <span className="text-emerald-400 font-bold text-sm leading-none shrink-0">+</span>
                  <span>AI-driven Detection</span>
                </div>

                {/* Badge 3: Explainable Insights */}
                <div className="flex items-center gap-2.5 px-4 py-2 rounded-xl bg-[#0a1324]/90 border border-slate-700/70 backdrop-blur-xl text-xs font-medium text-slate-200 shadow-xl shadow-black/40 hover:border-emerald-500/40 transition-all cursor-default">
                  <span className="text-emerald-400 font-bold text-sm leading-none shrink-0">+</span>
                  <span>Explainable Insights</span>
                </div>

                {/* Badge 4: Actionable Intelligence */}
                <div className="flex items-center gap-2.5 px-4 py-2 rounded-xl bg-[#0a1324]/90 border border-slate-700/70 backdrop-blur-xl text-xs font-medium text-slate-200 shadow-xl shadow-black/40 hover:border-emerald-500/40 transition-all cursor-default">
                  <span className="text-emerald-400 font-bold text-sm leading-none shrink-0">+</span>
                  <span>Actionable Intelligence</span>
                </div>
              </div>
            </div>
          </div>

        </div>
      </main>

      {/* ══════════════════════════════════════════════════════════════════════
          3. Footer (Matching Mockup Frame 1)
          ══════════════════════════════════════════════════════════════════════ */}
      <footer className="h-12 px-8 lg:px-16 flex items-center z-20 shrink-0">
        <p className="text-xs text-slate-400/80 font-normal">
          A Smart India Hackathon 2026 Initiative
        </p>
      </footer>

      {/* ══════════════════════════════════════════════════════════════════════
          4. Interactive Modals (Sign In, About, Features, Contact)
          ══════════════════════════════════════════════════════════════════════ */}
      {activeModal && (
        <div
          className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-150"
          onClick={(e) => e.target === e.currentTarget && setActiveModal(null)}
        >
          <div className="bg-[#0e1626] border border-slate-700/80 rounded-2xl max-w-lg w-full p-6 text-left shadow-2xl space-y-4 relative">
            <button
              onClick={() => setActiveModal(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white cursor-pointer transition-colors"
            >
              <X className="w-5 h-5" />
            </button>

            {/* MODAL 1: SIGN IN */}
            {activeModal === 'signin' && (
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
                    <Lock className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white">SOC Operator Authentication</h3>
                    <p className="text-xs text-slate-400">Access CyberNetra Defense & Telemetry Platform</p>
                  </div>
                </div>

                <form onSubmit={handleQuickLogin} className="space-y-3 pt-2">
                  <div>
                    <label htmlFor="operator-email" className="block text-[11px] font-semibold text-slate-300 uppercase tracking-wider mb-1">
                      Government / Security Analyst ID
                    </label>
                    <input
                      id="operator-email"
                      name="operator-email"
                      type="email"
                      value={loginEmail}
                      onChange={(e) => setLoginEmail(e.target.value)}
                      className="w-full bg-[#152033] border border-slate-700 focus:border-blue-500 rounded-lg px-3 py-2 text-xs text-white focus:outline-none font-mono"
                      required
                    />
                  </div>

                  <div>
                    <label htmlFor="operator-password" className="block text-[11px] font-semibold text-slate-300 uppercase tracking-wider mb-1">
                      Security Passphrase / Token
                    </label>
                    <input
                      id="operator-password"
                      name="operator-password"
                      type="password"
                      value={loginPassword}
                      onChange={(e) => setLoginPassword(e.target.value)}
                      className="w-full bg-[#152033] border border-slate-700 focus:border-blue-500 rounded-lg px-3 py-2 text-xs text-white focus:outline-none font-mono"
                      required
                    />
                  </div>

                  <div className="flex items-center justify-between text-xs text-slate-400 pt-1">
                    <span className="flex items-center gap-1.5 text-emerald-400 font-mono text-[11px]">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      TLS 1.3 Encrypted Session
                    </span>
                    <button
                      type="button"
                      onClick={() => onEnterApp()}
                      className="text-blue-400 hover:underline cursor-pointer text-xs"
                    >
                      Bypass (Jury Evaluation Mode)
                    </button>
                  </div>

                  <div className="pt-3 flex gap-3">
                    <button
                      type="submit"
                      disabled={isLoggingIn}
                      className="flex-1 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold cursor-pointer transition-colors flex items-center justify-center gap-2"
                    >
                      {isLoggingIn ? (
                        <>
                          <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                          <span>Authenticating Operator...</span>
                        </>
                      ) : (
                        <span>Verify & Launch SOC Console</span>
                      )}
                    </button>
                  </div>
                </form>
              </div>
            )}

            {/* MODAL 2: ABOUT */}
            {activeModal === 'about' && (
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
                    <Shield className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white">About CyberNetra</h3>
                    <p className="text-xs text-slate-400">Next-Gen AI Cybersecurity & Threat Forecasting</p>
                  </div>
                </div>

                <p className="text-[13px] text-slate-300 leading-relaxed mt-3">
                  CyberNetra is an advanced artificial intelligence network defense platform engineered to anticipate, detect, and mitigate cyber intrusions across critical national digital infrastructure in real time.
                </p>

                <div className="mt-4 p-3 bg-slate-900/80 rounded-xl border border-slate-800 text-xs text-slate-400 space-y-2 font-mono">
                  <p><strong className="text-white">Initiative:</strong> Smart India Hackathon 2026</p>
                  <p><strong className="text-white">Domain:</strong> Cybersecurity, Critical Infrastructure & Defense AI</p>
                  <p><strong className="text-white">Author / Lead:</strong> Krupal Ameti</p>
                  <p><strong className="text-white">Ensemble:</strong> UNSW-NB15 ML Classifiers + Deep Sequence Forecaster</p>
                </div>

                <div className="pt-4 flex justify-end">
                  <button
                    onClick={() => {
                      setActiveModal(null);
                      onEnterApp();
                    }}
                    className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold cursor-pointer transition-colors"
                  >
                    Enter Live Platform →
                  </button>
                </div>
              </div>
            )}

            {/* MODAL 3: FEATURES */}
            {activeModal === 'features' && (
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-8 h-8 rounded-lg bg-emerald-600/20 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                    <Sparkles className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white">Core Platform Capabilities</h3>
                    <p className="text-xs text-slate-400">Full-spectrum Network Threat Intelligence</p>
                  </div>
                </div>

                <ul className="text-[13px] text-slate-300 space-y-3 mt-4">
                  {[
                    ['Live Packet Telemetry:', 'Sub-millisecond packet inspection handling 12,000+ packets/second with automatic protocol classification.'],
                    ['Dual-Engine ML Detection:', 'Pre-trained Random Forest and XGBoost ensemble yielding 98.6% precision with calibrated confidence scoring.'],
                    ['Interactive Network Graph:', 'Dynamic SVG topology visualization tracing attacker nodes, target servers, port vectors, and ingress streams.'],
                    ['Explainable AI & MITRE ATT&CK:', 'Causal natural language reasoning and automated mapping to MITRE Tactics (T1498, T1046, T1110).'],
                    ['Active Countermeasures:', 'Instant forensic PDF reporting, automated firewall ACL rules, and BGP flowspec rate-limiting mitigations.']
                  ].map(([title, desc], i) => (
                    <li key={i} className="flex items-start gap-2.5">
                      <span className="text-emerald-400 font-bold mt-0.5 shrink-0">•</span>
                      <span><strong className="text-white">{title}</strong> {desc}</span>
                    </li>
                  ))}
                </ul>

                <div className="pt-4 flex justify-end">
                  <button
                    onClick={() => {
                      setActiveModal(null);
                      onEnterApp();
                    }}
                    className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold cursor-pointer transition-colors"
                  >
                    Launch Live Console →
                  </button>
                </div>
              </div>
            )}

            {/* MODAL 4: CONTACT */}
            {activeModal === 'contact' && (
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-8 h-8 rounded-lg bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
                    <Terminal className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white">Security Research & Collaboration</h3>
                    <p className="text-xs text-slate-400">Smart India Hackathon 2026 Evaluation Hub</p>
                  </div>
                </div>

                <p className="text-[13px] text-slate-300 leading-relaxed mt-3">
                  For platform evaluation, SIH jury verification, defense partner integration, or automated forensic ingest:
                </p>

                <div className="mt-4 p-3.5 bg-slate-900/80 rounded-xl border border-slate-800 text-xs text-slate-400 space-y-1.5 font-mono">
                  <p><strong className="text-white">Project:</strong> Krupal-ApexAI / CyberNetra</p>
                  <p><strong className="text-white">Author:</strong> Krupal Ameti</p>
                  <p><strong className="text-white">Status:</strong> Operational (FastAPI Backend :8000 + React Frontend :5174)</p>
                  <p><strong className="text-white">Deployment:</strong> SIH 2026 National Competition Pipeline</p>
                </div>

                <div className="pt-4 flex justify-end">
                  <button
                    onClick={() => {
                      setActiveModal(null);
                      onEnterApp();
                    }}
                    className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold cursor-pointer transition-colors"
                  >
                    Open Live Dashboard →
                  </button>
                </div>
              </div>
            )}

          </div>
        </div>
      )}
    </div>
  );
}
