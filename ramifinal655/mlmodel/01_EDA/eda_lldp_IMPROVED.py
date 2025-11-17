"""
IMPROVED Exploratory Data Analysis for LLDP Flow-Based Intrusion Detection
===========================================================================

This improved version addresses issues found in the initial EDA:
1. Removes features with >50% missing data
2. Removes zero-variance features
3. Removes highly correlated redundant features
4. Provides clean final feature set for modeling

Based on: Flow-Based SDN IDS Literature
Target Model: Random Forest Classifier
"""

import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from scipy.stats import spearmanr
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import VarianceThreshold
import warnings
import sys
warnings.filterwarnings('ignore')

# Fix Windows console encoding
if sys.platform == 'win32':
    import os
    os.system('chcp 65001 > nul 2>&1')
    sys.stdout.reconfigure(encoding='utf-8')

# Configuration
INPUT_FILE = r'c:\Users\User\Desktop\ramonzo\FINAL_LLDP_DATASET_COMPLETE_enriched.csv'
OUTPUT_FILE = r'c:\Users\User\Desktop\ramonzo\LLDP_ML_READY_FINAL.csv'
REPORT_FILE = r'c:\Users\User\Desktop\ramonzo\EDA_FINAL_REPORT.txt'

# Feature sets
ALL_FEATURES = [
    'packet_rate_inst', 'packet_rate_win', 'packet_rate',
    'burstiness_cv', 'size_z_src', 'time_delta',
    'age_since_first', 'tlv_density', 'ttl_dev',
    'ttl_anom_flag', 'is_lldp_mc'
]

DROP_COLUMNS = ['timestamp', 'time_epoch', 'eth_src', 'eth_dst',
                't_bin', 'count_win', 'inter_frame_delta', 'packet_size', 'ttl', 'tlv_count']

print("=" * 80)
print("IMPROVED LLDP FLOW-BASED IDS - EDA")
print("=" * 80)
print()

# ============================================================================
# STEP 1: Load and Clean
# ============================================================================
print("[STEP 1] Loading and initial cleaning...")
df_raw = pd.read_csv(INPUT_FILE)
print(f"  Original: {df_raw.shape[0]:,} rows × {df_raw.shape[1]} columns")

# Remove duplicates
df = df_raw.drop_duplicates()
print(f"  After deduplication: {len(df):,} rows ({df_raw.shape[0] - len(df):,} removed)")
print()

# ============================================================================
# STEP 2: Identify Available Features
# ============================================================================
print("[STEP 2] Identifying available behavioral features...")
available_features = [f for f in ALL_FEATURES if f in df.columns]
print(f"  Found {len(available_features)} features: {available_features}")
print()

# ============================================================================
# STEP 3: Remove High-Missing Features
# ============================================================================
print("[STEP 3] Removing features with >50% missing data...")
missing_threshold = 0.50
features_to_keep = []
features_removed_missing = []

for feature in available_features:
    missing_pct = df[feature].isnull().sum() / len(df)
    if missing_pct > missing_threshold:
        features_removed_missing.append((feature, missing_pct * 100))
        print(f"  ✗ Removing {feature:20s}: {missing_pct*100:6.2f}% missing")
    else:
        features_to_keep.append(feature)
        print(f"  ✓ Keeping  {feature:20s}: {missing_pct*100:6.2f}% missing")

print(f"\n  Removed {len(features_removed_missing)} high-missing features")
print()

# ============================================================================
# STEP 4: Impute Remaining Missing Values
# ============================================================================
print("[STEP 4] Imputing remaining missing values...")
for feature in features_to_keep:
    if df[feature].isnull().sum() > 0:
        missing_count = df[feature].isnull().sum()
        missing_pct = missing_count / len(df) * 100

        # Use median imputation for remaining missingness
        median_val = df[feature].median()
        df[feature].fillna(median_val, inplace=True)
        print(f"  Imputed {feature:20s}: {missing_count:5,} values ({missing_pct:5.2f}%) with median={median_val:.4f}")

remaining_missing = df[features_to_keep].isnull().sum().sum()
print(f"\n  ✓ Remaining missing values: {remaining_missing}")
print()

# ============================================================================
# STEP 5: Remove Zero-Variance Features
# ============================================================================
print("[STEP 5] Removing zero-variance (constant) features...")
features_removed_variance = []

for feature in features_to_keep[:]:  # Copy list for iteration
    unique_values = df[feature].nunique()
    if unique_values <= 1:
        features_removed_variance.append(feature)
        features_to_keep.remove(feature)
        print(f"  ✗ Removing {feature:20s}: Only {unique_values} unique value(s)")

if len(features_removed_variance) == 0:
    print("  ✓ No zero-variance features found")
print()

# ============================================================================
# STEP 6: Remove Highly Correlated Features
# ============================================================================
print("[STEP 6] Removing highly correlated features (|ρ| > 0.85)...")
correlation_matrix = df[features_to_keep].corr(method='spearman')
features_removed_correlation = []

# Identify pairs
high_corr_pairs = []
for i in range(len(correlation_matrix.columns)):
    for j in range(i+1, len(correlation_matrix.columns)):
        corr_value = correlation_matrix.iloc[i, j]
        if abs(corr_value) > 0.85:
            feat1 = correlation_matrix.columns[i]
            feat2 = correlation_matrix.columns[j]
            high_corr_pairs.append((feat1, feat2, corr_value))

# Remove one from each pair (keep first, remove second)
for feat1, feat2, corr_val in high_corr_pairs:
    if feat2 in features_to_keep:
        features_to_keep.remove(feat2)
        features_removed_correlation.append((feat2, feat1, corr_val))
        print(f"  ✗ Removing {feat2:20s}: Redundant with {feat1:20s} (ρ={corr_val:+.3f})")

if len(features_removed_correlation) == 0:
    print("  ✓ No highly correlated features found")
print()

# ============================================================================
# STEP 7: Final Feature Summary
# ============================================================================
print("[STEP 7] Final feature set summary...")
print(f"  Starting features: {len(available_features)}")
print(f"  Removed (missing data): {len(features_removed_missing)}")
print(f"  Removed (zero variance): {len(features_removed_variance)}")
print(f"  Removed (correlation): {len(features_removed_correlation)}")
print(f"  Final features: {len(features_to_keep)}")
print()
print("  Final feature set:")
for i, feat in enumerate(features_to_keep, 1):
    print(f"    {i:2d}. {feat}")
print()

# ============================================================================
# STEP 8: Class Distribution
# ============================================================================
print("[STEP 8] Analyzing class distribution...")
label_counts = df['label'].value_counts()
label_percentages = df['label'].value_counts(normalize=True) * 100

print("\n  Class Distribution:")
for label, count in label_counts.items():
    percentage = label_percentages[label]
    print(f"    {label:20s}: {count:6,} ({percentage:6.2f}%)")

max_ratio = label_counts.max() / label_counts.min()
print(f"\n  Imbalance ratio: {max_ratio:.2f}:1")
if max_ratio > 3:
    print("  → Recommendation: Use class_weight='balanced' in Random Forest")
print()

# ============================================================================
# STEP 9: Feature Statistics
# ============================================================================
print("[STEP 9] Computing feature statistics...")
summary_stats = df[features_to_keep].describe().T
summary_stats['skewness'] = df[features_to_keep].skew()
summary_stats['kurtosis'] = df[features_to_keep].kurtosis()

print("\n" + summary_stats.to_string())
print()

# ============================================================================
# STEP 10: Standardization
# ============================================================================
print("[STEP 10] Standardizing features (Z-score normalization)...")
X = df[features_to_keep].copy()
y = df['label'].copy()

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

df_final = pd.DataFrame(X_scaled, columns=features_to_keep, index=df.index)
df_final['label'] = y

print("  ✓ Standardization complete")
print(f"    Mean: {df_final[features_to_keep].mean().mean():.6f}")
print(f"    Std:  {df_final[features_to_keep].std().mean():.6f}")
print()

# ============================================================================
# STEP 11: Export
# ============================================================================
print("[STEP 11] Exporting final ML-ready dataset...")
df_final.to_csv(OUTPUT_FILE, index=False)
print(f"  ✓ Saved: {OUTPUT_FILE}")
print(f"    Shape: {df_final.shape[0]:,} rows × {df_final.shape[1]} columns")
print(f"    Features: {len(features_to_keep)}")
print()

# ============================================================================
# STEP 12: Generate Report
# ============================================================================
print("[STEP 12] Generating summary report...")
report = []
report.append("=" * 80)
report.append("IMPROVED LLDP FLOW-BASED IDS - FINAL EDA REPORT")
report.append("=" * 80)
report.append("")
report.append(f"Dataset: {INPUT_FILE}")
report.append(f"Date: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}")
report.append("")

report.append("1. DATA CLEANING SUMMARY")
report.append("-" * 80)
report.append(f"  Original rows: {df_raw.shape[0]:,}")
report.append(f"  Duplicates removed: {df_raw.shape[0] - len(df):,}")
report.append(f"  Final rows: {len(df):,}")
report.append("")

report.append("2. FEATURE SELECTION SUMMARY")
report.append("-" * 80)
report.append(f"  Initial features: {len(available_features)}")
report.append(f"  Final features: {len(features_to_keep)}")
report.append("")
report.append("  Removed due to high missing data (>50%):")
for feat, pct in features_removed_missing:
    report.append(f"    - {feat:20s} ({pct:.1f}% missing)")
if len(features_removed_missing) == 0:
    report.append("    (none)")
report.append("")
report.append("  Removed due to zero variance:")
for feat in features_removed_variance:
    report.append(f"    - {feat}")
if len(features_removed_variance) == 0:
    report.append("    (none)")
report.append("")
report.append("  Removed due to high correlation:")
for feat, corr_with, corr_val in features_removed_correlation:
    report.append(f"    - {feat:20s} (corr with {corr_with}: {corr_val:+.3f})")
if len(features_removed_correlation) == 0:
    report.append("    (none)")
report.append("")

report.append("3. FINAL FEATURE SET")
report.append("-" * 80)
for i, feat in enumerate(features_to_keep, 1):
    report.append(f"  {i:2d}. {feat}")
report.append("")

report.append("4. CLASS DISTRIBUTION")
report.append("-" * 80)
for label, count in label_counts.items():
    percentage = label_percentages[label]
    report.append(f"  {label:20s}: {count:6,} ({percentage:6.2f}%)")
report.append(f"  Imbalance ratio: {max_ratio:.2f}:1")
report.append("")

report.append("5. FEATURE STATISTICS")
report.append("-" * 80)
report.append(summary_stats.to_string())
report.append("")

report.append("6. NEXT STEPS")
report.append("-" * 80)
report.append("  1. Load LLDP_ML_READY_FINAL.csv")
report.append("  2. Split data (stratified 80/20)")
report.append("  3. Train Random Forest with class_weight='balanced'")
report.append("  4. Evaluate with F1-score, TPR, FPR, ROC-AUC")
report.append("  5. Tune hyperparameters if needed")
report.append("  6. Serialize model for Ryu controller")
report.append("")
report.append("=" * 80)

with open(REPORT_FILE, 'w', encoding='utf-8') as f:
    f.write('\n'.join(report))

print(f"  ✓ Saved: {REPORT_FILE}")
print()

# ============================================================================
# STEP 13: Visualization
# ============================================================================
print("[STEP 13] Generating visualizations...")

# Final correlation matrix
if len(features_to_keep) > 1:
    plt.figure(figsize=(10, 8))
    final_corr = df_final[features_to_keep].corr(method='spearman')
    sns.heatmap(final_corr, annot=True, fmt='.2f', cmap='coolwarm',
                center=0, square=True, linewidths=0.5)
    plt.title('Final Feature Correlation Matrix (After Cleanup)', fontsize=12, fontweight='bold')
    plt.tight_layout()
    plt.savefig(r'c:\Users\User\Desktop\ramonzo\correlation_final.png', dpi=300)
    print("  ✓ Saved: correlation_final.png")

# Class distribution
fig, ax = plt.subplots(1, 1, figsize=(10, 6))
label_counts.plot(kind='bar', ax=ax, color=sns.color_palette('Set2', len(label_counts)))
ax.set_title('Class Distribution - LLDP Attack Types', fontsize=14, fontweight='bold')
ax.set_ylabel('Count', fontsize=12)
ax.set_xlabel('Label', fontsize=12)
ax.tick_params(axis='x', rotation=45)
ax.grid(axis='y', alpha=0.3)
for i, v in enumerate(label_counts.values):
    ax.text(i, v + 50, str(v), ha='center', fontweight='bold')
plt.tight_layout()
plt.savefig(r'c:\Users\User\Desktop\ramonzo\class_distribution_final.png', dpi=300)
print("  ✓ Saved: class_distribution_final.png")

print()

# ============================================================================
# COMPLETION
# ============================================================================
print("=" * 80)
print("IMPROVED EDA COMPLETE")
print("=" * 80)
print()
print("Summary:")
print(f"  Input:  {df_raw.shape[0]:,} rows")
print(f"  Output: {len(df):,} rows × {len(features_to_keep)} features (+ label)")
print()
print("Files generated:")
print(f"  1. {OUTPUT_FILE}")
print(f"  2. {REPORT_FILE}")
print("  3. correlation_final.png")
print("  4. class_distribution_final.png")
print()
print("Ready for Random Forest training!")
print("=" * 80)
