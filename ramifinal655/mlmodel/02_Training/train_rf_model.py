"""
LLDP Flow-Based IDS - Random Forest Training & Evaluation
==========================================================

Complete implementation of model training and comprehensive evaluation
including all metrics required for SDN intrusion detection deployment.

Metrics Computed:
- Macro F1-Score
- Per-Class F1-Score
- False Positive Rate (FPR)
- Confusion Matrix
- Detection Latency (PacketIn → Decision)
- Controller Overhead (Processing Time per Event)

Aligned with Flow-Based SDN IDS literature.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
    roc_curve
)
import joblib
import time
import warnings
import sys
warnings.filterwarnings('ignore')

# Fix Windows console encoding
if sys.platform == 'win32':
    import os
    os.system('chcp 65001 > nul 2>&1')
    sys.stdout.reconfigure(encoding='utf-8')

# Configuration
INPUT_FILE = r'c:\Users\User\Desktop\ramonzo\LLDP_ML_READY_FINAL.csv'
MODEL_FILE = r'c:\Users\User\Desktop\ramonzo\lldp_rf_model.pkl'
METRICS_REPORT = r'c:\Users\User\Desktop\ramonzo\MODEL_EVALUATION_REPORT.txt'
RANDOM_STATE = 42

print("=" * 80)
print("LLDP FLOW-BASED IDS - RANDOM FOREST TRAINING & EVALUATION")
print("=" * 80)
print()

# ============================================================================
# STEP 1: Load Data
# ============================================================================
print("[STEP 1] Loading ML-ready dataset...")
df = pd.read_csv(INPUT_FILE)
print(f"  Dataset loaded: {df.shape[0]:,} rows × {df.shape[1]} columns")

X = df.drop(columns=['label'])
y = df['label']

feature_names = X.columns.tolist()
class_names = sorted(y.unique())

print(f"  Features: {len(feature_names)}")
print(f"    {', '.join(feature_names)}")
print(f"  Classes: {len(class_names)}")
print(f"    {', '.join(class_names)}")
print()

# ============================================================================
# STEP 2: Train-Test Split (Stratified)
# ============================================================================
print("[STEP 2] Splitting data (stratified 80/20)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=RANDOM_STATE
)

print(f"  Training set: {X_train.shape[0]:,} samples")
print(f"  Test set:     {X_test.shape[0]:,} samples")
print()

# Verify stratification
print("  Class distribution (train vs test):")
train_dist = y_train.value_counts(normalize=True).sort_index()
test_dist = y_test.value_counts(normalize=True).sort_index()
for cls in class_names:
    print(f"    {cls:15s}: Train={train_dist.get(cls, 0)*100:5.2f}%  Test={test_dist.get(cls, 0)*100:5.2f}%")
print()

# ============================================================================
# STEP 3: Train Random Forest Classifier
# ============================================================================
print("[STEP 3] Training Random Forest classifier...")
print("  Configuration:")
print("    - n_estimators: 100")
print("    - class_weight: balanced (handles 10.62:1 imbalance)")
print("    - random_state: 42")
print("    - n_jobs: -1 (all CPU cores)")
print()

rf_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=None,
    min_samples_split=2,
    min_samples_leaf=1,
    class_weight='balanced',  # Critical for handling class imbalance
    random_state=RANDOM_STATE,
    n_jobs=-1,
    verbose=0
)

# Measure training time
train_start = time.time()
rf_model.fit(X_train, y_train)
train_time = time.time() - train_start

print(f"  ✓ Training complete in {train_time:.2f} seconds")
print()

# ============================================================================
# STEP 4: Basic Accuracy Metrics
# ============================================================================
print("[STEP 4] Computing basic accuracy metrics...")

# Training accuracy
train_pred = rf_model.predict(X_train)
train_accuracy = accuracy_score(y_train, train_pred)

# Test accuracy
test_pred = rf_model.predict(X_test)
test_accuracy = accuracy_score(y_test, test_pred)

print(f"  Training Accuracy: {train_accuracy:.4f} ({train_accuracy*100:.2f}%)")
print(f"  Test Accuracy:     {test_accuracy:.4f} ({test_accuracy*100:.2f}%)")
print()

# Check for overfitting
if train_accuracy - test_accuracy > 0.10:
    print("  ⚠ WARNING: Potential overfitting detected (train-test gap > 10%)")
    print("    → Consider: Reduce max_depth or increase min_samples_leaf")
elif train_accuracy - test_accuracy > 0.05:
    print("  ⚠ NOTE: Moderate train-test gap (5-10%)")
else:
    print("  ✓ Good generalization (train-test gap < 5%)")
print()

# ============================================================================
# STEP 5: F1-Score Analysis
# ============================================================================
print("[STEP 5] Computing F1-Score metrics...")

# Macro F1 (equal weight to all classes)
f1_macro = f1_score(y_test, test_pred, average='macro')

# Weighted F1 (weighted by class support)
f1_weighted = f1_score(y_test, test_pred, average='weighted')

# Micro F1 (global average)
f1_micro = f1_score(y_test, test_pred, average='micro')

print(f"  F1-Score (Macro):    {f1_macro:.4f}")
print(f"  F1-Score (Weighted): {f1_weighted:.4f}")
print(f"  F1-Score (Micro):    {f1_micro:.4f}")
print()

# Per-class F1 scores
print("  Per-Class F1-Scores:")
precision, recall, f1, support = precision_recall_fscore_support(
    y_test, test_pred, labels=class_names, zero_division=0
)

for i, cls in enumerate(class_names):
    print(f"    {cls:15s}: F1={f1[i]:.4f}  Precision={precision[i]:.4f}  Recall={recall[i]:.4f}  Support={support[i]:4d}")
print()

# Identify weak classes
weak_classes = [(class_names[i], f1[i]) for i in range(len(class_names)) if f1[i] < 0.70]
if weak_classes:
    print("  ⚠ Classes with F1 < 0.70:")
    for cls, score in weak_classes:
        print(f"    - {cls}: {score:.4f}")
    print("    → Consider: SMOTE oversampling or hyperparameter tuning")
else:
    print("  ✓ All classes have F1 ≥ 0.70")
print()

# ============================================================================
# STEP 6: False Positive Rate (FPR) Analysis
# ============================================================================
print("[STEP 6] Computing False Positive Rate (FPR)...")

# Compute per-class FPR
fpr_per_class = {}
for cls in class_names:
    # True negatives: correctly predicted as NOT this class
    # False positives: incorrectly predicted AS this class
    y_true_binary = (y_test == cls).astype(int)
    y_pred_binary = (test_pred == cls).astype(int)

    # TN = (not cls in true) AND (not cls in pred)
    # FP = (not cls in true) AND (cls in pred)
    tn = ((y_true_binary == 0) & (y_pred_binary == 0)).sum()
    fp = ((y_true_binary == 0) & (y_pred_binary == 1)).sum()

    # FPR = FP / (FP + TN)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fpr_per_class[cls] = fpr

print("  Per-Class False Positive Rate:")
for cls, fpr in fpr_per_class.items():
    status = "✓" if fpr < 0.05 else "⚠" if fpr < 0.10 else "✗"
    print(f"    {status} {cls:15s}: {fpr:.4f} ({fpr*100:.2f}%)")

avg_fpr = np.mean(list(fpr_per_class.values()))
print(f"\n  Average FPR: {avg_fpr:.4f} ({avg_fpr*100:.2f}%)")

if avg_fpr < 0.05:
    print("  ✓ Excellent: FPR < 5% (production-ready)")
elif avg_fpr < 0.10:
    print("  ✓ Good: FPR < 10% (acceptable for IDS)")
else:
    print("  ⚠ WARNING: FPR > 10% (may cause alert fatigue)")
print()

# ============================================================================
# STEP 7: Confusion Matrix
# ============================================================================
print("[STEP 7] Generating confusion matrix...")

cm = confusion_matrix(y_test, test_pred, labels=class_names)

print("\n  Confusion Matrix:")
print("  " + " " * 17 + "Predicted")
print("  " + " " * 17 + "  ".join([f"{cls[:4]:>6s}" for cls in class_names]))

for i, true_cls in enumerate(class_names):
    row_label = f"  Actual {true_cls:10s}"
    row_values = "  ".join([f"{cm[i, j]:6d}" for j in range(len(class_names))])
    print(f"{row_label}  {row_values}")
print()

# Visualize confusion matrix
plt.figure(figsize=(10, 8))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=class_names, yticklabels=class_names,
            cbar_kws={'label': 'Count'})
plt.title('Confusion Matrix - LLDP Attack Classification', fontsize=14, fontweight='bold')
plt.ylabel('True Label', fontsize=12)
plt.xlabel('Predicted Label', fontsize=12)
plt.tight_layout()
plt.savefig(r'c:\Users\User\Desktop\ramonzo\confusion_matrix.png', dpi=300, bbox_inches='tight')
print("  ✓ Confusion matrix saved: confusion_matrix.png")
print()

# ============================================================================
# STEP 8: Detection Latency (Inference Time)
# ============================================================================
print("[STEP 8] Measuring detection latency...")

# Test on individual samples (simulating PacketIn events)
n_samples = 1000
sample_indices = np.random.choice(len(X_test), n_samples, replace=True)
X_latency_test = X_test.iloc[sample_indices]

latencies = []
for i in range(n_samples):
    sample = X_latency_test.iloc[i:i+1]

    start = time.perf_counter()
    prediction = rf_model.predict(sample)
    end = time.perf_counter()

    latency_ms = (end - start) * 1000  # Convert to milliseconds
    latencies.append(latency_ms)

latencies = np.array(latencies)

print(f"  Detection Latency (PacketIn → Decision):")
print(f"    Mean:   {latencies.mean():.4f} ms")
print(f"    Median: {np.median(latencies):.4f} ms")
print(f"    Min:    {latencies.min():.4f} ms")
print(f"    Max:    {latencies.max():.4f} ms")
print(f"    Std:    {latencies.std():.4f} ms")
print(f"    95th percentile: {np.percentile(latencies, 95):.4f} ms")
print(f"    99th percentile: {np.percentile(latencies, 99):.4f} ms")
print()

if latencies.mean() < 1.0:
    print("  ✓ Excellent: Mean latency < 1ms (real-time capable)")
elif latencies.mean() < 5.0:
    print("  ✓ Good: Mean latency < 5ms (suitable for SDN)")
elif latencies.mean() < 10.0:
    print("  ⚠ Acceptable: Mean latency < 10ms")
else:
    print("  ✗ WARNING: Mean latency > 10ms (may impact SDN performance)")
print()

# ============================================================================
# STEP 9: Controller Overhead (Batch Processing)
# ============================================================================
print("[STEP 9] Measuring controller overhead (batch processing)...")

# Test different batch sizes
batch_sizes = [1, 10, 50, 100, 500, 1000]
overhead_results = {}

for batch_size in batch_sizes:
    if batch_size > len(X_test):
        continue

    X_batch = X_test.iloc[:batch_size]

    # Measure processing time
    start = time.perf_counter()
    predictions = rf_model.predict(X_batch)
    end = time.perf_counter()

    total_time_ms = (end - start) * 1000
    per_event_ms = total_time_ms / batch_size
    throughput = batch_size / ((end - start) if (end - start) > 0 else 1e-6)

    overhead_results[batch_size] = {
        'total_ms': total_time_ms,
        'per_event_ms': per_event_ms,
        'throughput': throughput
    }

print("  Controller Overhead (Processing Time per Event):")
print(f"  {'Batch Size':>12s}  {'Total (ms)':>12s}  {'Per Event (ms)':>15s}  {'Throughput (events/s)':>23s}")
print("  " + "-" * 70)

for batch_size, metrics in overhead_results.items():
    print(f"  {batch_size:12d}  {metrics['total_ms']:12.4f}  {metrics['per_event_ms']:15.6f}  {metrics['throughput']:23.2f}")

print()

# Estimate max throughput
max_throughput = max([m['throughput'] for m in overhead_results.values()])
print(f"  Maximum Throughput: {max_throughput:,.0f} events/second")

if max_throughput > 10000:
    print("  ✓ Excellent: Can handle >10K events/sec")
elif max_throughput > 1000:
    print("  ✓ Good: Can handle >1K events/sec")
else:
    print("  ⚠ Limited: Throughput <1K events/sec")
print()

# ============================================================================
# STEP 10: Feature Importance
# ============================================================================
print("[STEP 10] Analyzing feature importance...")

importances = rf_model.feature_importances_
importance_df = pd.DataFrame({
    'feature': feature_names,
    'importance': importances
}).sort_values('importance', ascending=False)

print("\n  Feature Importance Ranking:")
for idx, row in importance_df.iterrows():
    bar_length = int(row['importance'] * 50)
    bar = '█' * bar_length
    print(f"    {row['feature']:20s}: {row['importance']:.4f}  {bar}")
print()

# Visualize feature importance
plt.figure(figsize=(10, 6))
plt.barh(importance_df['feature'], importance_df['importance'], color='steelblue')
plt.xlabel('Importance', fontsize=12)
plt.ylabel('Feature', fontsize=12)
plt.title('Random Forest Feature Importance - LLDP IDS', fontsize=14, fontweight='bold')
plt.grid(axis='x', alpha=0.3)
plt.tight_layout()
plt.savefig(r'c:\Users\User\Desktop\ramonzo\feature_importance.png', dpi=300, bbox_inches='tight')
print("  ✓ Feature importance plot saved: feature_importance.png")
print()

# ============================================================================
# STEP 11: Cross-Validation
# ============================================================================
print("[STEP 11] Performing 5-fold cross-validation...")

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
cv_scores = cross_val_score(rf_model, X, y, cv=cv, scoring='f1_macro', n_jobs=-1)

print(f"  Cross-Validation F1-Scores (Macro):")
for i, score in enumerate(cv_scores, 1):
    print(f"    Fold {i}: {score:.4f}")

print(f"\n  Mean CV F1-Score: {cv_scores.mean():.4f} (±{cv_scores.std():.4f})")

if cv_scores.std() < 0.05:
    print("  ✓ Excellent: Low variance across folds (<0.05)")
elif cv_scores.std() < 0.10:
    print("  ✓ Good: Moderate variance (<0.10)")
else:
    print("  ⚠ High variance (>0.10) - model may be unstable")
print()

# ============================================================================
# STEP 12: Save Model
# ============================================================================
print("[STEP 12] Saving trained model...")

joblib.dump(rf_model, MODEL_FILE)
print(f"  ✓ Model saved: {MODEL_FILE}")
print(f"    Size: {os.path.getsize(MODEL_FILE) / 1024:.2f} KB")
print()

# Test model loading
loaded_model = joblib.load(MODEL_FILE)
test_prediction = loaded_model.predict(X_test.iloc[:1])
print(f"  ✓ Model loading verified (test prediction: {test_prediction[0]})")
print()

# ============================================================================
# STEP 13: Generate Comprehensive Report
# ============================================================================
print("[STEP 13] Generating comprehensive evaluation report...")

report_lines = []
report_lines.append("=" * 80)
report_lines.append("LLDP FLOW-BASED IDS - MODEL EVALUATION REPORT")
report_lines.append("=" * 80)
report_lines.append("")
report_lines.append(f"Generated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}")
report_lines.append(f"Model: Random Forest Classifier")
report_lines.append(f"Dataset: {INPUT_FILE}")
report_lines.append("")

report_lines.append("1. DATASET SUMMARY")
report_lines.append("-" * 80)
report_lines.append(f"  Total samples: {len(df):,}")
report_lines.append(f"  Features: {len(feature_names)}")
report_lines.append(f"  Classes: {len(class_names)}")
report_lines.append(f"  Train/Test split: 80/20 (stratified)")
report_lines.append(f"  Training samples: {len(X_train):,}")
report_lines.append(f"  Test samples: {len(X_test):,}")
report_lines.append("")

report_lines.append("2. MODEL CONFIGURATION")
report_lines.append("-" * 80)
report_lines.append(f"  Algorithm: Random Forest")
report_lines.append(f"  n_estimators: 100")
report_lines.append(f"  class_weight: balanced")
report_lines.append(f"  Training time: {train_time:.2f} seconds")
report_lines.append("")

report_lines.append("3. ACCURACY METRICS")
report_lines.append("-" * 80)
report_lines.append(f"  Training Accuracy: {train_accuracy:.4f}")
report_lines.append(f"  Test Accuracy:     {test_accuracy:.4f}")
report_lines.append(f"  Overfitting gap:   {train_accuracy - test_accuracy:.4f}")
report_lines.append("")

report_lines.append("4. F1-SCORE METRICS")
report_lines.append("-" * 80)
report_lines.append(f"  F1-Score (Macro):    {f1_macro:.4f}")
report_lines.append(f"  F1-Score (Weighted): {f1_weighted:.4f}")
report_lines.append(f"  F1-Score (Micro):    {f1_micro:.4f}")
report_lines.append("")
report_lines.append("  Per-Class F1-Scores:")
for i, cls in enumerate(class_names):
    report_lines.append(f"    {cls:15s}: {f1[i]:.4f}")
report_lines.append("")

report_lines.append("5. FALSE POSITIVE RATE (FPR)")
report_lines.append("-" * 80)
for cls, fpr in fpr_per_class.items():
    report_lines.append(f"  {cls:15s}: {fpr:.4f} ({fpr*100:.2f}%)")
report_lines.append(f"  Average FPR: {avg_fpr:.4f}")
report_lines.append("")

report_lines.append("6. DETECTION LATENCY")
report_lines.append("-" * 80)
report_lines.append(f"  Mean:   {latencies.mean():.4f} ms")
report_lines.append(f"  Median: {np.median(latencies):.4f} ms")
report_lines.append(f"  95th percentile: {np.percentile(latencies, 95):.4f} ms")
report_lines.append(f"  99th percentile: {np.percentile(latencies, 99):.4f} ms")
report_lines.append("")

report_lines.append("7. CONTROLLER OVERHEAD")
report_lines.append("-" * 80)
report_lines.append(f"  Maximum Throughput: {max_throughput:,.0f} events/second")
report_lines.append("")
report_lines.append("  Batch Processing Performance:")
for batch_size, metrics in overhead_results.items():
    report_lines.append(f"    Batch {batch_size:4d}: {metrics['per_event_ms']:.6f} ms/event")
report_lines.append("")

report_lines.append("8. FEATURE IMPORTANCE")
report_lines.append("-" * 80)
for idx, row in importance_df.iterrows():
    report_lines.append(f"  {row['feature']:20s}: {row['importance']:.4f}")
report_lines.append("")

report_lines.append("9. CROSS-VALIDATION")
report_lines.append("-" * 80)
report_lines.append(f"  Mean CV F1-Score: {cv_scores.mean():.4f} (±{cv_scores.std():.4f})")
report_lines.append("")

report_lines.append("10. MODEL FILES")
report_lines.append("-" * 80)
report_lines.append(f"  Model: {MODEL_FILE}")
report_lines.append(f"  Size: {os.path.getsize(MODEL_FILE) / 1024:.2f} KB")
report_lines.append("")

report_lines.append("=" * 80)
report_lines.append("END OF REPORT")
report_lines.append("=" * 80)

with open(METRICS_REPORT, 'w', encoding='utf-8') as f:
    f.write('\n'.join(report_lines))

print(f"  ✓ Report saved: {METRICS_REPORT}")
print()

# ============================================================================
# COMPLETION SUMMARY
# ============================================================================
print("=" * 80)
print("TRAINING & EVALUATION COMPLETE")
print("=" * 80)
print()
print("Key Results:")
print(f"  ✓ Test Accuracy:      {test_accuracy:.4f} ({test_accuracy*100:.2f}%)")
print(f"  ✓ F1-Score (Macro):   {f1_macro:.4f}")
print(f"  ✓ Average FPR:        {avg_fpr:.4f} ({avg_fpr*100:.2f}%)")
print(f"  ✓ Detection Latency:  {latencies.mean():.4f} ms (mean)")
print(f"  ✓ Max Throughput:     {max_throughput:,.0f} events/sec")
print()
print("Files Generated:")
print(f"  1. {MODEL_FILE}")
print(f"  2. {METRICS_REPORT}")
print("  3. confusion_matrix.png")
print("  4. feature_importance.png")
print()
print("Next Step: Deploy model to Ryu controller for real-time detection")
print("=" * 80)
