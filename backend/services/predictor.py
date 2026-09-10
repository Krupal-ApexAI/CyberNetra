"""
ML Prediction Pipeline for CyberNetra Log Analysis.

Maps parsed log events → UNSW-NB15 feature vectors → RF binary detection
→ XGBoost attack classification → feature evidence extraction.

IMPORTANT: This module does NOT retrain models. It uses pre-loaded artifacts
from model_loader.py for inference only.
"""

import hashlib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional, Tuple
from collections import Counter


# ──────────────────────────────────────────────
# UNSW-NB15 Feature Descriptions & Mapping
# ──────────────────────────────────────────────
# Full list of 43 features expected by the trained models.
# Features are mapped from parsed log data where possible.
# Features that cannot be derived from raw logs use documented defaults.

UNSW_FEATURE_DESCRIPTIONS = {
    "id": "Row identifier",
    "dur": "Record total duration",
    "proto": "Transaction protocol (categorical)",
    "service": "Network service type (categorical)",
    "state": "Connection state (categorical)",
    "spkts": "Source-to-destination packet count",
    "dpkts": "Destination-to-source packet count",
    "sbytes": "Source-to-destination bytes",
    "dbytes": "Destination-to-source bytes",
    "rate": "Connections per second in the time window",
    "sttl": "Source-to-destination time-to-live",
    "dttl": "Destination-to-source time-to-live",
    "sload": "Source bits per second",
    "dload": "Destination bits per second",
    "sloss": "Source packets retransmitted or dropped",
    "dloss": "Destination packets retransmitted or dropped",
    "sinpkt": "Source inter-packet arrival time (ms)",
    "dinpkt": "Destination inter-packet arrival time (ms)",
    "sjit": "Source jitter (ms)",
    "djit": "Destination jitter (ms)",
    "swin": "Source TCP window advertisement",
    "stcpb": "Source TCP base sequence number",
    "dtcpb": "Destination TCP base sequence number",
    "dwin": "Destination TCP window advertisement",
    "tcprtt": "TCP connection setup round-trip time",
    "synack": "Time between SYN and SYN_ACK",
    "ackdat": "Time between SYN_ACK and ACK",
    "smean": "Mean of source packet size",
    "dmean": "Mean of destination packet size",
    "trans_depth": "Pipelined depth of connection (HTTP)",
    "response_body_len": "Content size of server HTTP response",
    "ct_srv_src": "No. connections same service and source in 100 connections",
    "ct_state_ttl": "No. connections same state according to specific TTL ranges",
    "ct_dst_ltm": "No. connections same destination in 100 connections",
    "ct_src_dport_ltm": "No. connections same source and destination port in 100",
    "ct_dst_sport_ltm": "No. connections same destination and source port in 100",
    "ct_dst_src_ltm": "No. connections same destination and source in 100",
    "is_ftp_login": "1 if FTP session with user/pass, else 0",
    "ct_ftp_cmd": "No. flows with FTP command in session",
    "ct_flw_http_mthd": "No. flows with HTTP methods (GET/POST)",
    "ct_src_ltm": "No. connections same source in 100 connections",
    "ct_srv_dst": "No. connections same service and destination in 100",
    "is_sm_ips_ports": "1 if source and destination IPs and ports are equal",
}

# Protocol → numeric mapping used in UNSW-NB15
PROTOCOL_MAP = {
    "TCP": "tcp",
    "UDP": "udp",
    "ICMP": "icmp",
    "HTTP": "tcp",
    "HTTPS": "tcp",
    "SSH": "tcp",
    "FTP": "tcp",
    "DNS": "udp",
    "SMTP": "tcp",
    "TLS": "tcp",
}

# Port → service name mapping (UNSW-NB15 conventions)
PORT_SERVICE_MAP = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "ssl",
    445: "smb",
    993: "ssl",
    995: "ssl",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    8080: "http",
    8443: "ssl",
}

# Default state for TCP connections
DEFAULT_STATE = "CON"


def map_event_to_features(
    event: Dict[str, Any],
    event_index: int,
    batch_size: int,
    batch_context: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Map a single parsed log event to the full UNSW-NB15 feature vector.

    Args:
        event: Parsed log event from log_parser
        event_index: Index within the batch (used for 'id' feature)
        batch_size: Total events in batch (used for rate estimation)
        batch_context: Shared context computed from the full batch

    Returns:
        Dict with all 43 UNSW-NB15 feature names as keys

    Note:
        Features that cannot be directly obtained from the log line are
        derived from batch context or use documented defaults. Each such
        derivation is recorded in the feature mapping and should never
        be presented as "observed from the log" in explanations.
    """
    protocol = event.get("protocol", "TCP")
    proto_val = PROTOCOL_MAP.get(protocol, protocol.lower())

    dst_port = event.get("dst_port") or 0
    src_port = event.get("src_port") or 0

    # Determine service from destination port
    service = PORT_SERVICE_MAP.get(dst_port, "-")

    # Determine connection state
    state = DEFAULT_STATE

    # Bytes: use parsed values or estimate from batch context
    sbytes = event.get("bytes_sent") or batch_context.get("est_sbytes", 48)
    dbytes = event.get("bytes_received") or batch_context.get("est_dbytes", 0)

    # Duration
    dur = event.get("duration") or batch_context.get("est_duration", 0.001)

    # Packets
    spkts = event.get("packets") or max(1, sbytes // 1460 + 1) if sbytes else 1
    dpkts = max(1, dbytes // 1460 + 1) if dbytes > 0 else 0

    # Rate: connections per second estimated from batch
    rate = batch_context.get("rate", batch_size)

    # TTL defaults (common OS values)
    sttl = 62   # Linux default minus a few hops
    dttl = 254  # Server typical

    # Load calculations (bits per second)
    sload = (sbytes * 8 / dur) if dur > 0 else 0
    dload = (dbytes * 8 / dur) if dur > 0 else 0

    # Loss (no retransmission info from logs)
    sloss = 0
    dloss = 0

    # Inter-packet timing
    sinpkt = (dur * 1000 / spkts) if spkts > 0 and dur > 0 else 0
    dinpkt = (dur * 1000 / dpkts) if dpkts > 0 and dur > 0 else 0

    # Jitter (no multi-packet timing info from logs)
    sjit = 0.0
    djit = 0.0

    # TCP window (defaults for standard OS implementations)
    swin = 255
    dwin = 255

    # TCP base sequence numbers (not available from logs)
    stcpb = 0
    dtcpb = 0

    # TCP round-trip time estimates
    tcprtt = dur if dur > 0 else 0.001
    synack = tcprtt / 2 if proto_val == "tcp" else 0
    ackdat = tcprtt / 2 if proto_val == "tcp" else 0

    # Mean packet sizes
    smean = sbytes // spkts if spkts > 0 else 0
    dmean = dbytes // dpkts if dpkts > 0 else 0

    # HTTP features
    trans_depth = 1 if service in ("http", "ssl") else 0
    response_body_len = dbytes if service in ("http", "ssl") else 0

    # Connection tracking features (derived from batch context)
    src_ip = event.get("src_ip", "0.0.0.0")
    dst_ip = event.get("dst_ip", "0.0.0.0")

    ct_srv_src = batch_context.get("ct_srv_src", {}).get((service, src_ip), 1)
    ct_state_ttl = batch_context.get("ct_state_ttl", 1)
    ct_dst_ltm = batch_context.get("ct_dst_ltm", {}).get(dst_ip, 1)
    ct_src_dport_ltm = batch_context.get("ct_src_dport_ltm", {}).get((src_ip, dst_port), 1)
    ct_dst_sport_ltm = batch_context.get("ct_dst_sport_ltm", {}).get((dst_ip, src_port), 1)
    ct_dst_src_ltm = batch_context.get("ct_dst_src_ltm", {}).get((dst_ip, src_ip), 1)
    ct_src_ltm = batch_context.get("ct_src_ltm", {}).get(src_ip, 1)
    ct_srv_dst = batch_context.get("ct_srv_dst", {}).get((service, dst_ip), 1)

    # FTP features
    is_ftp_login = 1 if service == "ftp" else 0
    ct_ftp_cmd = 1 if service in ("ftp", "ftp-data") else 0

    # HTTP method count
    ct_flw_http_mthd = 1 if service in ("http", "ssl") else 0

    # Same IPs and ports check
    is_sm_ips_ports = 1 if (src_ip == dst_ip and src_port == dst_port) else 0

    return {
        "id": event_index + 1,
        "dur": dur,
        "proto": proto_val,
        "service": service,
        "state": state,
        "spkts": spkts,
        "dpkts": dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "rate": rate,
        "sttl": sttl,
        "dttl": dttl,
        "sload": sload,
        "dload": dload,
        "sloss": sloss,
        "dloss": dloss,
        "sinpkt": sinpkt,
        "dinpkt": dinpkt,
        "sjit": sjit,
        "djit": djit,
        "swin": swin,
        "stcpb": stcpb,
        "dtcpb": dtcpb,
        "dwin": dwin,
        "tcprtt": tcprtt,
        "synack": synack,
        "ackdat": ackdat,
        "smean": smean,
        "dmean": dmean,
        "trans_depth": trans_depth,
        "response_body_len": response_body_len,
        "ct_srv_src": ct_srv_src,
        "ct_state_ttl": ct_state_ttl,
        "ct_dst_ltm": ct_dst_ltm,
        "ct_src_dport_ltm": ct_src_dport_ltm,
        "ct_dst_sport_ltm": ct_dst_sport_ltm,
        "ct_dst_src_ltm": ct_dst_src_ltm,
        "is_ftp_login": is_ftp_login,
        "ct_ftp_cmd": ct_ftp_cmd,
        "ct_flw_http_mthd": ct_flw_http_mthd,
        "ct_src_ltm": ct_src_ltm,
        "ct_srv_dst": ct_srv_dst,
        "is_sm_ips_ports": is_sm_ips_ports,
    }


def compute_batch_context(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute batch-level context for UNSW-NB15 connection tracking features.

    These features count occurrences of IP/port/service combinations
    within a time window. We derive them from the batch of parsed events.
    """
    context: Dict[str, Any] = {}
    n = len(events)

    # Rate: events per second (estimate using time span or batch size)
    timestamps = []
    for e in events:
        ts = e.get("timestamp")
        if ts:
            try:
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
                    try:
                        dt = pd.Timestamp(ts)
                        timestamps.append(dt)
                        break
                    except Exception:
                        continue
            except Exception:
                pass

    if len(timestamps) >= 2:
        time_span = (max(timestamps) - min(timestamps)).total_seconds()
        context["rate"] = n / max(time_span, 0.001)
        context["est_duration"] = max(time_span / n, 0.001)
    else:
        context["rate"] = float(n)
        context["est_duration"] = 0.001

    # Default byte estimates
    context["est_sbytes"] = 48  # Typical SYN packet
    context["est_dbytes"] = 0

    # Connection tracking counters (capped at 100 per UNSW-NB15 spec)
    ct_srv_src = Counter()
    ct_dst_ltm = Counter()
    ct_src_dport_ltm = Counter()
    ct_dst_sport_ltm = Counter()
    ct_dst_src_ltm = Counter()
    ct_src_ltm = Counter()
    ct_srv_dst = Counter()

    for e in events:
        src_ip = e.get("src_ip", "0.0.0.0")
        dst_ip = e.get("dst_ip", "0.0.0.0")
        dst_port = e.get("dst_port") or 0
        src_port = e.get("src_port") or 0
        service = PORT_SERVICE_MAP.get(dst_port, "-")

        ct_srv_src[(service, src_ip)] += 1
        ct_dst_ltm[dst_ip] += 1
        ct_src_dport_ltm[(src_ip, dst_port)] += 1
        ct_dst_sport_ltm[(dst_ip, src_port)] += 1
        ct_dst_src_ltm[(dst_ip, src_ip)] += 1
        ct_src_ltm[src_ip] += 1
        ct_srv_dst[(service, dst_ip)] += 1

    # Cap at 100 connections as per UNSW-NB15 semantics
    context["ct_srv_src"] = {k: min(v, 100) for k, v in ct_srv_src.items()}
    context["ct_dst_ltm"] = {k: min(v, 100) for k, v in ct_dst_ltm.items()}
    context["ct_src_dport_ltm"] = {k: min(v, 100) for k, v in ct_src_dport_ltm.items()}
    context["ct_dst_sport_ltm"] = {k: min(v, 100) for k, v in ct_dst_sport_ltm.items()}
    context["ct_dst_src_ltm"] = {k: min(v, 100) for k, v in ct_dst_src_ltm.items()}
    context["ct_src_ltm"] = {k: min(v, 100) for k, v in ct_src_ltm.items()}
    context["ct_srv_dst"] = {k: min(v, 100) for k, v in ct_srv_dst.items()}
    context["ct_state_ttl"] = min(n, 100)

    return context


def extract_feature_evidence(
    feature_values: Dict[str, Any],
    model,
    top_n: int = 8,
) -> List[Dict[str, Any]]:
    """
    Extract the most important features contributing to the model's prediction.

    Uses model.feature_importances_ (available for RF and XGBoost) combined
    with the actual feature values to identify the top contributing features.

    Returns list of {"feature", "value", "importance"} dicts.
    """
    evidence = []

    if not hasattr(model, "feature_importances_"):
        return evidence

    importances = model.feature_importances_
    feature_names = [k for k in feature_values.keys()
                     if k not in ("proto", "service", "state")]

    # For numerical features, pair importance with value
    for feat_name in feature_names:
        if feat_name in feature_values:
            # Find the feature index in the model's feature list
            val = feature_values[feat_name]
            if isinstance(val, str):
                continue  # Skip categorical for importance display
            evidence.append({
                "feature": feat_name,
                "value": float(val),
                "importance": 0.0,  # Will be filled below
            })

    # Map importances to numerical features
    # The binary model was trained on all 43 features including encoded categoricals
    # feature_importances_ length may differ from raw feature count due to encoding
    # We'll use the feature names from feature_info to map correctly
    try:
        from backend.models.model_loader import model_loader
        expected_features = model_loader.get_binary_features()
        numerical = model_loader.get_numerical_features()

        # If the model has same number of importances as features (no encoding),
        # map directly
        if len(importances) == len(expected_features):
            imp_map = dict(zip(expected_features, importances))
            for item in evidence:
                item["importance"] = float(imp_map.get(item["feature"], 0.0))
        else:
            # Fallback: distribute importances proportionally
            total_imp = float(np.sum(importances))
            if total_imp > 0:
                # Use the top importances from the model
                top_indices = np.argsort(importances)[-top_n:][::-1]
                for idx in top_indices:
                    if idx < len(expected_features):
                        fname = expected_features[idx]
                        if fname in feature_values and not isinstance(feature_values[fname], str):
                            found = False
                            for item in evidence:
                                if item["feature"] == fname:
                                    item["importance"] = float(importances[idx])
                                    found = True
                                    break
                            if not found:
                                evidence.append({
                                    "feature": fname,
                                    "value": float(feature_values.get(fname, 0)),
                                    "importance": float(importances[idx]),
                                })
    except Exception:
        pass

    # Sort by importance descending, take top N
    evidence.sort(key=lambda x: x["importance"], reverse=True)
    return evidence[:top_n]


def predict_batch(
    parsed_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Run the full ML prediction pipeline on a batch of parsed log events.

    Pipeline:
        1. Compute batch context (connection tracking stats)
        2. Map each event to UNSW-NB15 features
        3. Validate feature set matches model expectations
        4. Binary classification (RF, threshold 0.30)
        5. Attack classification (XGBoost, only for attack events)
        6. Feature evidence extraction
        7. Aggregate batch summary

    Returns structured prediction results for each event + batch summary.
    """
    from backend.models.model_loader import model_loader

    if not model_loader.is_unsw_pipeline_ready():
        raise RuntimeError(
            "UNSW-NB15 ML pipeline not loaded. "
            "Ensure all model .pkl files are in backend/models/"
        )

    expected_features = model_loader.get_binary_features()
    threshold = model_loader.binary_threshold

    if not parsed_events:
        return {
            "events": [],
            "total_events": 0,
            "normal_events": 0,
            "attack_events": 0,
            "dominant_attack": None,
            "batch_features": [],
        }

    # Step 1: Compute batch context
    batch_context = compute_batch_context(parsed_events)
    batch_size = len(parsed_events)

    # Step 2: Map all events to feature vectors
    feature_dicts = []
    for idx, event in enumerate(parsed_events):
        feat = map_event_to_features(event, idx, batch_size, batch_context)
        feature_dicts.append(feat)

    # Step 3: Create DataFrame and validate features
    df = pd.DataFrame(feature_dicts)

    # Validate feature set
    missing = set(expected_features) - set(df.columns)
    extra = set(df.columns) - set(expected_features)
    if missing:
        raise ValueError(
            f"Missing features for model: {missing}. "
            f"Expected {len(expected_features)} features."
        )
    if extra:
        df = df.drop(columns=list(extra), errors="ignore")

    # Reorder to expected feature order
    df = df[expected_features]

    # Step 4: Binary classification
    binary_model = model_loader.binary_model
    probas = binary_model.predict_proba(df)
    attack_probs = probas[:, 1]
    predictions = (attack_probs >= threshold).astype(int)

    # Step 5 & 6: Process each event
    results = []
    attack_types = []

    for idx, event in enumerate(parsed_events):
        is_attack = predictions[idx] == 1
        attack_prob = float(attack_probs[idx])
        detection_confidence = attack_prob if is_attack else (1.0 - attack_prob)

        result = {
            "event_index": idx,
            "timestamp": event.get("timestamp"),
            "source_ip": event.get("src_ip"),
            "source_port": event.get("src_port"),
            "destination_ip": event.get("dst_ip"),
            "destination_port": event.get("dst_port"),
            "protocol": event.get("protocol"),
            "prediction": "Attack" if is_attack else "Normal",
            "detection_confidence": round(detection_confidence, 4),
            "threshold": threshold,
            "attack_type": None,
            "attack_confidence": None,
            "risk_level": "LOW",
            "raw_log": event.get("raw_log"),
            "important_features": [],
            "parsing_warnings": event.get("parsing_warnings", []),
        }

        if is_attack:
            # Run attack classifier
            try:
                attack_type, attack_conf = _classify_attack(
                    df.iloc[[idx]], feature_dicts[idx]
                )
                result["attack_type"] = attack_type
                result["attack_confidence"] = round(attack_conf, 4)
                attack_types.append(attack_type)
            except Exception as e:
                result["attack_type"] = "Unknown"
                result["attack_confidence"] = 0.0
                result["parsing_warnings"].append(
                    f"Attack classification failed: {str(e)}"
                )

            # Extract feature evidence
            result["important_features"] = extract_feature_evidence(
                feature_dicts[idx], binary_model
            )

            # Determine risk level
            result["risk_level"] = _compute_risk_level(
                attack_prob, result.get("attack_confidence", 0)
            )
        else:
            result["risk_level"] = "LOW"

        results.append(result)

    # Batch summary
    normal_count = int(np.sum(predictions == 0))
    attack_count = int(np.sum(predictions == 1))
    dominant_attack = None
    if attack_types:
        counter = Counter(attack_types)
        dominant_attack = counter.most_common(1)[0][0]

    return {
        "events": results,
        "total_events": len(results),
        "normal_events": normal_count,
        "attack_events": attack_count,
        "dominant_attack": dominant_attack,
        "batch_features": feature_dicts,
    }


def _classify_attack(
    features_row: pd.DataFrame,
    feature_dict: Dict[str, Any],
) -> Tuple[str, float]:
    """
    Run the XGBoost attack-family classifier on a single event.
    Uses the attack preprocessor for feature transformation.
    """
    from backend.models.model_loader import model_loader

    attack_model = model_loader.attack_model
    preprocessor = model_loader.attack_preprocessor
    label_encoder = model_loader.label_encoder

    if attack_model is None:
        raise RuntimeError("Attack model not loaded")

    # Get attack features (same list as binary)
    attack_features = model_loader.get_attack_features()
    attack_df = features_row[attack_features].copy()

    # Apply preprocessor if available
    if preprocessor is not None:
        try:
            transformed = preprocessor.transform(attack_df)
            pred = attack_model.predict(transformed)
            probas = attack_model.predict_proba(transformed)
        except Exception:
            # Fallback: try direct prediction
            pred = attack_model.predict(attack_df)
            probas = attack_model.predict_proba(transformed)
    else:
        pred = attack_model.predict(attack_df)
        probas = attack_model.predict_proba(attack_df)

    # Decode label
    predicted_class = int(pred[0])
    confidence = float(np.max(probas[0]))

    if label_encoder is not None:
        try:
            attack_name = label_encoder.inverse_transform([predicted_class])[0]
        except Exception:
            attack_name = f"Category_{predicted_class}"
    else:
        categories = model_loader.get_attack_categories()
        attack_name = (
            categories[predicted_class]
            if predicted_class < len(categories)
            else f"Category_{predicted_class}"
        )

    return attack_name, confidence


def _compute_risk_level(detection_conf: float, attack_conf: float) -> str:
    """Compute risk level from detection and attack classification confidence."""
    avg_conf = (detection_conf + (attack_conf or detection_conf)) / 2

    if avg_conf >= 0.85:
        return "CRITICAL"
    elif avg_conf >= 0.65:
        return "HIGH"
    elif avg_conf >= 0.45:
        return "MEDIUM"
    else:
        return "LOW"


def generate_analysis_id(logs_text: str) -> str:
    """Generate a unique analysis ID from the log content hash + timestamp."""
    import time
    hash_input = f"{logs_text[:200]}_{time.time()}"
    return f"CNA-{hashlib.sha256(hash_input.encode()).hexdigest()[:12].upper()}"
