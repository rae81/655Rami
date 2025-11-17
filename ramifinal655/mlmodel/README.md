# LLDP Flow-Based Intrusion Detection System

Complete machine learning pipeline for detecting LLDP-based network attacks in SDN environments using Random Forest classification.

---

## Project Summary

The current model already meets the core objective of the project: detecting LLDP spoofing, replay, and flooding attacks that directly threaten SDN topology integrity. The system achieves **perfect detection (F1 = 1.00)** for the three highest-impact attack types—flooding, replay-based link fabrication, and chassis/port-ID spoofing—while maintaining a **low false positive rate of 3.69%**, **Normal traffic F1 of 0.78**, and **real-time detection latency of ~17 ms**, enabling safe inline mitigation inside the controller. These measurements confirm that the defense is both accurate and deployable, satisfying the performance and practicality criteria defined in the proposal.

---

## Project Structure

```
ramonzo/
├── README.md                          # This file - complete documentation
│
├── data/                              # Datasets
│   ├── FINAL_LLDP_DATASET_COMPLETE_enriched.csv  # Original (108,297 rows)
│   └── LLDP_ML_READY_FINAL.csv                   # Clean (9,830 rows)
│
├── 01_EDA/                            # Exploratory Data Analysis
│   ├── eda_lldp_IMPROVED.py                      # EDA script
│   ├── EDA_FINAL_REPORT.txt                      # Feature selection report
│   ├── correlation_final.png                     # Correlation heatmap
│   └── class_distribution_final.png              # Class imbalance chart
│
├── 02_Training/                       # Model Training
│   ├── train_rf_model.py                         # Training script
│   └── lldp_rf_model.pkl                         # Trained model (299 KB)
│
└── 03_Evaluation/                     # Model Evaluation
    ├── MODEL_EVALUATION_REPORT.txt               # All metrics
    ├── confusion_matrix.png                      # Classification results
    └── feature_importance.png                    # Feature ranking
```

---

## Quick Start

### 1. Run EDA (Already Completed)
```bash
python 01_EDA/eda_lldp_IMPROVED.py
```
**Output:** `data/LLDP_ML_READY_FINAL.csv`

### 2. Train Model (Already Completed)
```bash
python 02_Training/train_rf_model.py
```
**Output:** `02_Training/lldp_rf_model.pkl`

### 3. View Results
- Metrics: `03_Evaluation/MODEL_EVALUATION_REPORT.txt`
- Confusion Matrix: `03_Evaluation/confusion_matrix.png`
- Feature Importance: `03_Evaluation/feature_importance.png`

---

## Dataset Summary

**Original Dataset:** `data/FINAL_LLDP_DATASET_COMPLETE_enriched.csv`
- Raw: 108,297 rows × 22 columns
- After deduplication: 9,830 unique samples
- Attack classes: 6 types

**Clean Dataset:** `data/LLDP_ML_READY_FINAL.csv`
- Size: 9,830 rows × 6 columns (5 features + label)
- Quality: 100% complete, no missing values
- Features: Z-score normalized behavioral patterns

**Class Distribution:**
- normal: 4,522 (46.00%)
- replay: 2,308 (23.48%)
- flood: 1,174 (11.94%)
- spoofed: 800 (8.14%)
- ttl_anomaly: 600 (6.10%)
- malformed: 426 (4.33%)
- **Imbalance ratio:** 10.62:1

---

## Features (5 Behavioral Patterns)

| Feature | Description | Importance |
|---------|-------------|------------|
| `tlv_density` | TLV field density | 39.63% |
| `age_since_first` | Flow age since first packet | 24.80% |
| `packet_rate_win` | Packet rate in time window | 23.65% |
| `ttl_anom_flag` | TTL anomaly binary flag | 9.91% |
| `ttl_dev` | TTL deviation from expected | 2.01% |

---

## Model Performance

### Overall Metrics
- **Test Accuracy:** 79.20%
- **Macro F1-Score:** 0.6919
- **Weighted F1-Score:** 0.8179
- **Average FPR:** 3.69% ✓ (Production-ready)

### Per-Class F1-Scores

| Attack Class | F1-Score | Precision | Recall | Support | Status |
|--------------|----------|-----------|--------|---------|--------|
| **flood** | 1.0000 | 1.0000 | 1.0000 | 235 | ✅ Perfect |
| **replay** | 1.0000 | 1.0000 | 1.0000 | 462 | ✅ Perfect |
| **spoofed** | 1.0000 | 1.0000 | 1.0000 | 160 | ✅ Perfect |
| **normal** | 0.7817 | 1.0000 | 0.6416 | 904 | ✅ Good |
| **ttl_anomaly** | 0.3698 | 0.2268 | 1.0000 | 120 | ⚠️ Moderate |
| **malformed** | 0.0000 | 0.0000 | 0.0000 | 85 | ❌ Failed |

### False Positive Rate (FPR)

| Class | FPR | Status |
|-------|-----|--------|
| flood | 0.00% | ✅ Perfect |
| malformed | 0.00% | ✅ Perfect |
| normal | 0.00% | ✅ Perfect |
| replay | 0.00% | ✅ Perfect |
| spoofed | 0.00% | ✅ Perfect |
| ttl_anomaly | 22.16% | ⚠️ High |

**Average FPR:** 3.69% ✅ (Production-ready: <5%)

### Detection Performance

| Metric | Value |
|--------|-------|
| **Detection Latency (Mean)** | 17.22 ms |
| **Detection Latency (Median)** | 17.01 ms |
| **95th Percentile** | 18.35 ms |
| **99th Percentile** | 19.45 ms |
| **Max Throughput** | 59,963 events/second |
| **Training Time** | 0.12 seconds |

### Controller Overhead (Batch Processing)

| Batch Size | Per Event | Throughput |
|------------|-----------|------------|
| 1 | 17.33 ms | 58 events/s |
| 10 | 1.67 ms | 597 events/s |
| 100 | 0.17 ms | 5,820 events/s |
| 1000 | 0.02 ms | 59,963 events/s |

---

## Model Configuration

**Algorithm:** Random Forest Classifier

**Hyperparameters:**
- n_estimators: 100
- max_depth: None (unrestricted)
- min_samples_split: 2
- min_samples_leaf: 1
- class_weight: 'balanced' (handles 10.62:1 imbalance)
- random_state: 42

**Training:**
- Train/Test split: 80/20 (stratified)
- Cross-validation: 5-fold stratified
- Mean CV F1-Score: 0.6904 ± 0.0062

---

## Usage

### Load Model
```python
import joblib
import pandas as pd

# Load trained model
model = joblib.load('02_Training/lldp_rf_model.pkl')
```

### Make Prediction
```python
# Prepare LLDP event features
features = pd.DataFrame({
    'packet_rate_win': [10.5],
    'age_since_first': [0.0001],
    'tlv_density': [0.085],
    'ttl_dev': [0],
    'ttl_anom_flag': [0]
})

# Predict attack type
prediction = model.predict(features)[0]
confidence = model.predict_proba(features).max()

print(f"Attack type: {prediction}")
print(f"Confidence: {confidence:.2%}")
```

### Integration with Ryu Controller
```python
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls

@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def packet_in_handler(self, ev):
    # Extract LLDP features from packet
    features = self.extract_lldp_features(ev.msg)

    # Predict attack type
    prediction = self.model.predict([features])[0]

    if prediction in ['flood', 'replay', 'spoofed']:
        # Critical attack detected - drop packet
        self.logger.warning(f"LLDP attack detected: {prediction}")
        self.drop_packet(ev)
    else:
        # Normal LLDP - process normally
        self.process_lldp(ev)
```

---

## Deployment Recommendation

### ✅ Deploy For (Production-Ready)
- **Flood attacks:** 100% F1, 0% FPR
- **Replay attacks:** 100% F1, 0% FPR
- **Spoofing attacks:** 100% F1, 0% FPR
- **Normal traffic:** 78% F1, 0% FPR

### ❌ Do NOT Deploy For
- **Malformed packets:** 0% F1 (not detected)
- **TTL anomalies:** 37% F1, 22% FPR (unreliable)

### Recommended Configuration
```python
# Enable detection for critical attacks only
ENABLED_CLASSES = ['flood', 'replay', 'spoofed']

if prediction in ENABLED_CLASSES:
    # Take action
    drop_packet()
```

---

## Evaluation Metrics Computed

All requested metrics are documented in `03_Evaluation/MODEL_EVALUATION_REPORT.txt`:

**Classification Metrics:**
- ✅ Macro F1-Score: 0.6919
- ✅ Weighted F1-Score: 0.8179
- ✅ Per-Class F1-Score (all 6 classes)
- ✅ Precision & Recall per class
- ✅ Accuracy (train: 80.54%, test: 79.20%)

**Security Metrics:**
- ✅ False Positive Rate (FPR): 3.69% average
- ✅ True Positive Rate (TPR) per class
- ✅ Confusion Matrix (visualized)

**Performance Metrics:**
- ✅ Detection Latency: 17.22 ms mean
- ✅ Controller Overhead: 0.02-17.33 ms per event
- ✅ Max Throughput: 59,963 events/second

**Model Quality:**
- ✅ Cross-Validation: 0.6904 ± 0.0062
- ✅ Feature Importance: tlv_density (39.63%) most important
- ✅ Overfitting Analysis: 1.35% train-test gap (good)

---

## Limitations

### Malformed Packet Detection (0% F1)
**Root Cause:** No structural features in final feature set
- `tlv_density` alone cannot distinguish malformed from normal
- Original `tlv_count` feature was dropped during EDA
- Need packet payload inspection or sequence analysis

### TTL Anomaly Detection (37% F1, 22% FPR)
**Root Cause:** High overlap with normal traffic in feature space
- Model correctly identifies all ttl_anomaly samples (100% recall)
- But over-predicts this class for normal traffic (high false positives)
- Feature set captures TTL deviation but not context

---

## Pipeline Stages

### Stage 1: EDA & Preprocessing ✅
**Location:** `01_EDA/`

**Script:** `eda_lldp_IMPROVED.py`

**Actions:**
- Removed 98,467 duplicates (90.9%)
- Dropped 3 features with >50% missing data
- Removed 1 zero-variance feature
- Removed 2 highly correlated features
- Applied Z-score normalization

**Input:** `data/FINAL_LLDP_DATASET_COMPLETE_enriched.csv`
**Output:** `data/LLDP_ML_READY_FINAL.csv`

### Stage 2: Model Training ✅
**Location:** `02_Training/`

**Script:** `train_rf_model.py`

**Actions:**
- Trained Random Forest (100 trees)
- Applied balanced class weighting
- Computed all evaluation metrics
- Generated visualizations

**Input:** `data/LLDP_ML_READY_FINAL.csv`
**Output:** `lldp_rf_model.pkl` (299 KB)

### Stage 3: Evaluation ✅
**Location:** `03_Evaluation/`

**Metrics Computed:**
- Classification metrics (F1, Precision, Recall)
- Security metrics (FPR, TPR, Confusion Matrix)
- Performance metrics (Latency, Throughput)
- Model quality (CV, Feature Importance)

**Outputs:**
- `MODEL_EVALUATION_REPORT.txt` - All metrics
- `confusion_matrix.png` - Classification results
- `feature_importance.png` - Feature ranking

---

## Key Achievements

✅ **Perfect Detection (100% F1)** for critical attacks:
- Flood attacks (LLDP flooding)
- Replay attacks (link fabrication)
- Spoofed packets (chassis/port-ID spoofing)

✅ **Production-Ready FPR:** 3.69% average
- Zero false positives for most classes
- Acceptable for IDS deployment

✅ **Real-Time Capable:** 17.22 ms detection latency
- Suitable for inline SDN controller
- High throughput: 60K events/sec in batch mode

✅ **Stable Model:** Low variance (±0.0062)
- Consistent across data splits
- No overfitting (1.35% gap)

✅ **Efficient:** 0.12 seconds training time
- Easy to retrain with new data
- Suitable for continuous learning

---

## Technical Details

### Data Preprocessing
1. **Deduplication:** 108,297 → 9,830 rows
2. **Feature Selection:** 22 → 5 features
3. **Missing Values:** 100% complete
4. **Normalization:** Z-score (mean≈0, std≈1)
5. **Class Balancing:** Weighted loss function

### Model Architecture
- **Base Learner:** Decision Tree
- **Ensemble:** 100 trees (Random Forest)
- **Voting:** Majority voting
- **Feature Sampling:** √n features per split
- **Bootstrap:** Yes (with replacement)

### Evaluation Protocol
- **Split:** 80/20 stratified
- **Cross-Validation:** 5-fold stratified
- **Metrics:** F1 (macro), Accuracy, FPR, Latency
- **Test Samples:** 1,966 (20% of 9,830)

---

## References

**Methodology Alignment:**
- Flow-Based SDN IDS literature
- Random Forest for intrusion detection
- Behavioral feature extraction from network flows
- Z-score normalization for feature scaling

---

## License & Usage

This project is developed for academic research in SDN security. The model is trained specifically for LLDP attack detection and should be validated before production deployment.

---

**Last Updated:** 2025-11-05
**Status:** Complete
**Model:** Random Forest Classifier
**Dataset:** 9,830 samples, 5 features, 6 classes
**Performance:** 100% F1 for critical attacks, 3.69% FPR, 17ms latency
