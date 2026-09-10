import React, { useState, useEffect } from 'react';
import {
  UploadCloud,
  FileText,
  Database,
  Cpu,
  Play,
  CheckCircle2,
  Layers,
  Terminal,
  FileSpreadsheet,
  FileCode,
  Sparkles,
  RefreshCw,
  Sliders,
  Check,
  AlertCircle
} from 'lucide-react';
import { fetchDatasets, fetchDatasetPreview, uploadDatasetFile, trainModel } from '../services/api';

export default function ModelRegistryView({ modelInfo, onModelTrained }) {
  const [datasets, setDatasets] = useState([]);
  const [selectedDataset, setSelectedDataset] = useState('ds-unsw');
  const [previewData, setPreviewData] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadMessage, setUploadMessage] = useState('');
  
  // Model Training State
  const [architecture, setArchitecture] = useState('LSTM Sequence Forecaster');
  const [epochs, setEpochs] = useState(5);
  const [isTraining, setIsTraining] = useState(false);
  const [trainingResult, setTrainingResult] = useState(null);
  const [trainingProgress, setTrainingProgress] = useState(0);

  // Load available datasets on mount
  useEffect(() => {
    loadDatasets();
  }, []);

  // Reload preview whenever selectedDataset changes
  useEffect(() => {
    if (selectedDataset) {
      fetchDatasetPreview(selectedDataset).then((res) => {
        setPreviewData(res);
      });
    }
  }, [selectedDataset]);

  const loadDatasets = async () => {
    const list = await fetchDatasets();
    setDatasets(list);
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    setUploadMessage(`Ingesting and parsing '${file.name}'...`);

    try {
      const res = await uploadDatasetFile(file);
      setUploadMessage(res.message);
      await loadDatasets();
    } catch (err) {
      setUploadMessage(`Upload failed: ${err.message}`);
    } finally {
      setIsUploading(false);
    }
  };

  const handleStartTraining = async () => {
    setIsTraining(true);
    setTrainingResult(null);
    setTrainingProgress(15);

    const activeDs = datasets.find((d) => d.id === selectedDataset);
    const dsName = activeDs ? activeDs.name : 'UNSW_NB15_telemetry_sample.csv';

    // Simulate progressive training updates
    const interval = setInterval(() => {
      setTrainingProgress((prev) => {
        if (prev >= 90) {
          clearInterval(interval);
          return 90;
        }
        return prev + 25;
      });
    }, 450);

    try {
      const result = await trainModel({
        architecture,
        dataset_name: dsName,
        epochs: Number(epochs),
        learning_rate: 0.001
      });

      clearInterval(interval);
      setTrainingProgress(100);
      setTrainingResult(result);
      if (onModelTrained) onModelTrained(result);
    } catch (err) {
      console.error("Training failed:", err);
    } finally {
      setIsTraining(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Top Section Banner */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 bg-gradient-to-r from-slate-900/90 via-[#0b0f19] to-indigo-950/30">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-inner">
              <Database className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-slate-100 font-sans">
                  Dataset Ingestion & AI Model Training Hub
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/90 text-cyan-300 border border-cyan-500/30">
                  ML / DL Pipeline
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Ingest network traffic datasets (.csv, .pcap, .pdf), extract temporal flow features, and train sequence prediction models
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-mono px-3 py-1.5 rounded-xl bg-slate-900/80 border border-slate-800 text-slate-300 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>Pipeline: <strong className="text-emerald-300">Ready</strong></span>
            </span>
          </div>
        </div>
      </div>

      {/* 2. Step 1: Input Dataset Uploader & Benchmark Selector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Drag & Drop Uploader */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800/60 pb-3 mb-3">
              <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <UploadCloud className="w-4 h-4 text-cyan-400" />
                Upload Input Dataset
              </h3>
              <span className="text-[10px] font-mono text-slate-400">Step 1</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed mb-4">
              Upload custom flow capture files or cybersecurity incident reports to ingest into the training database.
            </p>

            {/* Upload Dropzone */}
            <label className="border-2 border-dashed border-slate-700/80 hover:border-cyan-500/60 rounded-xl p-5 flex flex-col items-center justify-center gap-2 cursor-pointer bg-[#070b12]/60 hover:bg-slate-900/40 transition-all group">
              <div className="p-3 rounded-full bg-slate-900 group-hover:bg-cyan-500/10 text-slate-400 group-hover:text-cyan-400 transition-colors">
                <UploadCloud className="w-6 h-6" />
              </div>
              <div className="text-center">
                <span className="text-xs font-medium text-slate-200 group-hover:text-cyan-300">
                  Click to browse or drop file
                </span>
                <p className="text-[10px] text-slate-500 mt-0.5">
                  Supports .csv, .pcap, .pdf, .json (up to 50MB)
                </p>
              </div>
              <input
                type="file"
                className="hidden"
                accept=".csv,.pdf,.json,.pcap,.txt"
                onChange={handleFileUpload}
                disabled={isUploading}
              />
            </label>

            {uploadMessage && (
              <div className="mt-3 text-[11px] font-mono text-cyan-300 bg-cyan-950/40 border border-cyan-500/30 p-2.5 rounded-xl flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" />
                <span className="truncate">{uploadMessage}</span>
              </div>
            )}
          </div>

          <div className="text-[11px] text-slate-500 font-mono flex items-center justify-between pt-2 border-t border-slate-800/60">
            <span>Storage: backend/data/uploads/</span>
            <span className="text-cyan-400">Local DB</span>
          </div>
        </div>

        {/* Right: Available Datasets Selector */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800/60 pb-3 mb-3">
              <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <FileSpreadsheet className="w-4 h-4 text-indigo-400" />
                Available Ingested Telemetry Datasets
              </h3>
              <button
                onClick={loadDatasets}
                className="text-slate-400 hover:text-slate-200 text-xs flex items-center gap-1 focus:outline-none"
              >
                <RefreshCw className="w-3 h-3" />
                <span>Refresh</span>
              </button>
            </div>

            {/* List of Datasets */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {datasets.map((ds) => {
                const isSelected = selectedDataset === ds.id;
                const isPdf = ds.name.endsWith('.pdf');

                return (
                  <div
                    key={ds.id}
                    onClick={() => setSelectedDataset(ds.id)}
                    className={`p-3.5 rounded-xl border transition-all cursor-pointer flex flex-col justify-between ${
                      isSelected
                        ? 'bg-gradient-to-b from-cyan-950/60 to-slate-900 border-cyan-500/60 shadow-md shadow-cyan-950/40'
                        : 'bg-slate-900/40 hover:bg-slate-900/80 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-black/40 text-slate-400">
                          {isPdf ? 'PDF / ADVISORY' : 'FLOW CSV'}
                        </span>
                        {isSelected && (
                          <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                        )}
                      </div>
                      <h4 className="text-xs font-bold text-slate-200 truncate mb-1" title={ds.name}>
                        {ds.name}
                      </h4>
                      <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed mb-2">
                        {ds.description}
                      </p>
                    </div>

                    <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] font-mono text-slate-400">
                      <span>{ds.records_count} records</span>
                      <span className="text-cyan-400 font-semibold">{ds.size}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="text-[11px] text-slate-400 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span>Active Training Source: <strong className="text-slate-200 font-mono">{datasets.find(d => d.id === selectedDataset)?.name || selectedDataset}</strong></span>
          </div>
        </div>
      </div>

      {/* 3. Ingested Data Preview Table */}
      {previewData && previewData.rows && previewData.rows.length > 0 && (
        <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800/60 pb-3">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              Ingested Feature Extraction Table (Sample Flow Ingress)
            </h3>
            <span className="text-xs font-mono text-slate-400">
              Showing {previewData.rows.length} parsed telemetry rows
            </span>
          </div>

          <div className="overflow-x-auto custom-scrollbar">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800/80 text-slate-400 text-[11px]">
                  <th className="py-2 px-3">Time</th>
                  <th className="py-2 px-3">Source IP</th>
                  <th className="py-2 px-3">Dest IP</th>
                  <th className="py-2 px-3">Proto</th>
                  <th className="py-2 px-3">Packets</th>
                  <th className="py-2 px-3">Volume (KB)</th>
                  <th className="py-2 px-3">Connections</th>
                  <th className="py-2 px-3">Failed Logins</th>
                  <th className="py-2 px-3">Class / Threat</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40 text-slate-300">
                {previewData.rows.map((r, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-2 px-3 text-slate-400">{r.timestamp}</td>
                    <td className="py-2 px-3 text-cyan-300">{r.source_ip}</td>
                    <td className="py-2 px-3">{r.destination_ip}</td>
                    <td className="py-2 px-3 text-slate-400">{r.protocol || 'TCP'}</td>
                    <td className="py-2 px-3 font-semibold">{r.packet_count}</td>
                    <td className="py-2 px-3">{r.traffic_volume}</td>
                    <td className="py-2 px-3">{r.connection_attempts}</td>
                    <td className="py-2 px-3 text-rose-400">{r.failed_login_attempts}</td>
                    <td className="py-2 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                        r.attack_type === 'Normal'
                          ? 'bg-emerald-950/70 text-emerald-400 border border-emerald-500/30'
                          : r.attack_type === 'BruteForce'
                          ? 'bg-orange-950/70 text-orange-400 border border-orange-500/30'
                          : r.attack_type === 'DDoS_Flood'
                          ? 'bg-rose-950/70 text-rose-400 border border-rose-500/30'
                          : 'bg-amber-950/70 text-amber-400 border border-amber-500/30'
                      }`}>
                        {r.attack_type || 'Observed'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 4. Model Training Controls & Progress */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800/60 pb-4 gap-2">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              Train & Fine-Tune Forecasting Model
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Select temporal sequence architecture and train on the active dataset to forecast impending attacks
            </p>
          </div>

          <button
            onClick={handleStartTraining}
            disabled={isTraining}
            className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-slate-900 font-bold text-xs tracking-wide shadow-lg shadow-cyan-500/25 transition-all cursor-pointer disabled:opacity-50"
          >
            {isTraining ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                <span>Training in Progress...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current text-slate-950" />
                <span>Launch Model Training</span>
              </>
            )}
          </button>
        </div>

        {/* Hyperparameter Inputs */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs text-slate-400 mb-1.5 font-medium">
              Neural Architecture
            </label>
            <select
              value={architecture}
              onChange={(e) => setArchitecture(e.target.value)}
              className="w-full bg-[#070b12] border border-slate-700 rounded-xl px-3 py-2 text-xs text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
            >
              <option value="LSTM Sequence Forecaster">LSTM Sequence Forecaster (Temporal State)</option>
              <option value="Transformer World Model">Transformer World Model (Attention-Based)</option>
              <option value="Graph Neural Network (GNN)">Graph Neural Network (Host Topology)</option>
              <option value="Random Forest Ensemble">Random Forest Heuristic Ensemble</option>
            </select>
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1.5 font-medium">
              Training Epochs
            </label>
            <select
              value={epochs}
              onChange={(e) => setEpochs(e.target.value)}
              className="w-full bg-[#070b12] border border-slate-700 rounded-xl px-3 py-2 text-xs text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
            >
              <option value="3">3 Epochs (Fast Demo)</option>
              <option value="5">5 Epochs (Standard Convergence)</option>
              <option value="10">10 Epochs (Deep Fine-Tuning)</option>
            </select>
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1.5 font-medium">
              Learning Rate & Optimizer
            </label>
            <div className="w-full bg-[#070b12]/80 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-400 font-mono">
              Adam (lr = 0.001, weight_decay = 1e-4)
            </div>
          </div>
        </div>

        {/* Training Progress Bar */}
        {isTraining && (
          <div className="space-y-2 pt-2">
            <div className="flex justify-between text-xs font-mono">
              <span className="text-cyan-400">Processing Epochs & Extracting Temporal Attention...</span>
              <span className="text-slate-300">{trainingProgress}%</span>
            </div>
            <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-indigo-500 transition-all duration-300"
                style={{ width: `${trainingProgress}%` }}
              />
            </div>
          </div>
        )}

        {/* Training Convergence Result Terminal */}
        {trainingResult && (
          <div className="bg-[#070b12] rounded-xl border border-slate-800 p-4 space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2 text-emerald-400">
              <div className="flex items-center gap-2 font-bold">
                <CheckCircle2 className="w-4 h-4" />
                <span>Training Converged Successfully</span>
              </div>
              <span className="text-[11px] text-slate-400">Checkpoint: {trainingResult.model_name}</span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 py-1">
              <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase">Final Accuracy</span>
                <p className="text-sm font-bold text-emerald-400">{trainingResult.final_accuracy}%</p>
              </div>
              <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase">Training Loss</span>
                <p className="text-sm font-bold text-cyan-300">{trainingResult.final_loss}</p>
              </div>
              <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase">Validation F1-Score</span>
                <p className="text-sm font-bold text-indigo-300">{trainingResult.f1_score}</p>
              </div>
              <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase">Deployment Path</span>
                <p className="text-xs text-slate-300 truncate">saved_models/</p>
              </div>
            </div>

            {/* Epoch Convergence Log Stream */}
            <div className="space-y-1 text-[11px] text-slate-400 pt-1 border-t border-slate-800/60">
              {trainingResult.training_history && trainingResult.training_history.map((h, i) => (
                <div key={i} className="flex justify-between">
                  <span>Epoch {h.epoch}/{trainingResult.epochs_completed} ? loss: <strong className="text-slate-300">{h.loss}</strong> - accuracy: <strong className="text-emerald-400">{h.accuracy}%</strong></span>
                  <span className="text-slate-500">val_loss: {h.val_loss} - val_acc: {h.val_accuracy}%</span>
                </div>
              ))}
            </div>

            <div className="pt-2 text-[11px] text-cyan-300 flex items-center gap-1.5">
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span>Model automatically hot-swapped into backend engine. Live forecast requests will now utilize this trained checkpoint!</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
