# LLDP IDS for SDN Controllers

Complete ML-based intrusion detection system for LLDP attacks in Software-Defined Networks.

## Overview

Detects and mitigates LLDP-based attacks (flood, replay, spoofing) using Random Forest classification with real-time packet interception.

**Model Performance:**
- F1-Score: 1.0 (flood, replay, spoofed)
- False Positive Rate: 3.69%
- Detection Latency: ~17ms
- Throughput: 59,963 pkt/s

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run IDS
```bash
# With topology discovery (recommended)
bash run_ids.sh

# Or manually
ryu-manager --observe-links ryu.topology.switches lldp_ids_system.py
```

### 3. Monitor
```bash
tail -f lldp_ids_alerts.log
```

### 4. Benchmark
```bash
python3 benchmark_and_plots.py
```

## Files

```
ramifinal655/
├── lldp_ids_system.py         # Main IDS (460 lines, YAML config integrated)
├── config.yaml                # Runtime configuration
├── requirements.txt           # Python dependencies
├── run_ids.sh                 # Deployment script (checks model, sets env)
├── benchmark_and_plots.py     # Performance analysis (headless plotting)
├── mlmodel/02_Training/
│   └── lldp_rf_model.pkl      # Trained model (305KB) - Required on controller VM
└── logs/ runs/                # Runtime outputs (auto-created)
```

**Controller VM Requirements:**
- All files above must be present
- Model file at: `mlmodel/02_Training/lldp_rf_model.pkl` (305KB)
- Python 3.8+ with scikit-learn==1.3.0

## Configuration

Edit `config.yaml`:
```yaml
detection:
  enabled_classes: ["flood", "replay", "spoofed"]
  expected_ttl: 120
  window_sec: 10

mitigation:
  drop_flow_idle_sec: 30

logging:
  file: "lldp_ids_alerts.log"
  rotate_mb: 10
```

## Attack Detection

```
ATTACK: FLOOD
Confidence: 99.8% | Latency: 17.23ms
Rate: 15.2 pkt/s
ACTION: DROPPED + TEMPORARY BLOCK FLOW INSTALLED
```

## Benchmarking

Outputs to `runs/<timestamp>/`:
- `metrics.csv` - Performance metrics
- `events.csv` - All classified events
- `latency_hist.png` - Latency distribution
- `attacks_bar.png` - Attack type breakdown
- `throughput.png` - Events/second over time

## Open Source Components

- **Ryu Framework** - github.com/faucetsdn/ryu
- **LLDP Handling** - github.com/macauleycheng/AOS_OF_Example
- **ML Integration** - github.com/ranauzairahmed/MininetIDS
- **IDS Structure** - github.com/arsheen/IDS-on-SDN-using-Machine-Learning

## Requirements

- Python 3.8+
- Ryu 4.34+
- OpenFlow 1.3
- scikit-learn 1.3.0

## License

Apache 2.0
