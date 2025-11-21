# LLDP IDS Dataset Analysis Report

**Dataset:** `FINAL_LLDP_DATASET_COMPLETE_enriched.csv`
**Location:** `ramifinal655/mlmodel/data/`
**Date:** 2025-11-21

---

## Executive Summary

✅ **Dataset is VALID and ready for processing**
- Total rows: **108,297** (exactly as expected)
- File size: **18 MB**
- Class distribution: **Matches expected distribution**
- Data quality: **Good, with some features requiring handling**

---

## 1. Dataset Overview

### File Statistics
- **Total rows:** 108,297 data rows (+ 1 header = 108,298 lines)
- **Total columns:** 22 features
- **File size:** 18 MB
- **Duplicate rows:** 2,365 (2.2% of dataset)

### Column List
1. timestamp
2. time_epoch
3. eth_src (source MAC address)
4. eth_dst (destination MAC address)
5. packet_size
6. ttl (Time To Live)
7. tlv_count (Type-Length-Value count)
8. label (attack class)
9. inter_frame_delta
10. packet_rate_inst
11. packet_rate_win
12. ttl_dev (TTL deviation)
13. ttl_anom_flag (TTL anomaly flag)
14. tlv_density
15. is_lldp_mc (is LLDP multicast)
16. age_since_first
17. size_z_src (Z-score of size)
18. burstiness_cv (coefficient of variation)
19. time_delta
20. packet_rate
21. t_bin (time bin)
22. count_win (count in window)

---

## 2. Class Distribution

| Class | Count | Percentage | Imbalance Ratio |
|-------|------:|----------:|-----------------:|
| **flood** | 87,866 | 81.2% | 206:1 (vs malformed) |
| **replay** | 12,560 | 11.6% | - |
| **normal** | 6,045 | 5.6% | - |
| **spoofed** | 800 | 0.7% | - |
| **ttl_anomaly** | 600 | 0.6% | - |
| **malformed** | 426 | 0.4% | Smallest class |
| **TOTAL** | 108,297 | 100.0% | - |

### Class Imbalance Analysis
- **Imbalance Ratio:** 206:1 (flood vs malformed)
- **Majority class:** flood (81.2%)
- **Minority classes:** malformed (426), ttl_anomaly (600), spoofed (800)
- **Impact:** Requires class balancing techniques (class_weight='balanced', stratified sampling)

---

## 3. Feature Completeness Analysis

### ✅ Complete Features (100% filled)
These features have **no missing values** and are safe to use:

1. timestamp, time_epoch
2. eth_src, eth_dst
3. packet_size, ttl, tlv_count
4. **label** (target variable)
5. packet_rate_win, ttl_dev, ttl_anom_flag
6. tlv_density, is_lldp_mc, age_since_first
7. time_delta, packet_rate, t_bin, count_win

**Total:** 18 features with complete data

### ⚠️ Partially Missing Features

| Feature | Filled | Missing | % Missing | Status |
|---------|-------:|--------:|----------:|--------|
| **inter_frame_delta** | 104,116 | 4,181 | 3.9% | ✅ Acceptable |
| **burstiness_cv** | 6,858 | 101,439 | 93.7% | ❌ Drop or impute |
| **packet_rate_inst** | 2,618 | 105,679 | 97.6% | ❌ Drop or impute |
| **size_z_src** | 0 | 108,297 | 100.0% | ❌ **DROP** |

### 🔍 Missing Data Patterns by Class

#### packet_rate_inst (97.6% missing overall):
- flood: 179 / 87,866 (0.2%)
- normal: 1,639 / 6,045 (27.1%)
- replay: 800 / 12,560 (6.4%)
- spoofed, ttl_anomaly, malformed: **0 rows** (completely missing)

#### burstiness_cv (93.7% missing overall):
- flood: 266 / 87,866 (0.3%)
- normal: 4,334 / 6,045 (71.7%)
- replay: 2,258 / 12,560 (18.0%)
- spoofed, ttl_anomaly, malformed: **0 rows** (completely missing)

#### size_z_src (100% missing):
- **Completely empty column** - must be dropped

---

## 4. Feature Value Distributions

### Key Distinguishing Features by Class

#### TTL (Time To Live)
- **Normal:** TTL = 120 (standard)
- **Flood:** TTL = 4, 8, 10, etc. (very low)
- **TTL Anomaly:** TTL = 0 (zero!)
- **Spoofed:** TTL = 120 (normal, harder to detect)
- **Malformed:** TTL = 120 (normal)
- **Replay:** TTL = 120 (normal)
- **Unique TTL values:** 124 different values

#### Packet Size
- Most packets: 60 bytes
- Spoofed packets: 64 bytes (larger due to extra TLV)
- Range: 60-64 bytes

#### TLV Count
- Normal/Flood/TTL anomaly/Malformed: 5 TLVs
- Spoofed/Replay: 6 TLVs (extra TLV)

#### Packet Rate Window
- Normal: 25.4 packets/sec (high rate)
- Flood: 3.33 packets/sec (burst pattern)
- Spoofed/TTL anomaly/Malformed: 0.033 packets/sec (very low)
- Replay: 11.3 packets/sec (medium)

#### Count Window
- Normal: 762 (high window count)
- Flood: 100 (lower window count)
- Others: 1 (single packet or low count)

---

## 5. Data Quality Issues

### Issue 1: Duplicate Rows
- **Count:** 2,365 duplicate rows (2.2%)
- **Impact:** Minimal, but should be removed during preprocessing
- **Action:** Use `df.drop_duplicates()` in notebook

### Issue 2: Missing Data in Behavioral Features
- **Features:** burstiness_cv (93.7% missing), packet_rate_inst (97.6% missing)
- **Impact:** These features are only available for normal, flood, and replay classes
- **Problem:** Cannot use these features to detect spoofed, ttl_anomaly, or malformed attacks
- **Action:** **Drop these features** from the model OR handle with class-aware imputation

### Issue 3: Completely Empty Feature
- **Feature:** size_z_src (100% missing)
- **Impact:** Unusable feature that will cause errors
- **Action:** **Must drop this column** before training

### Issue 4: Class Imbalance
- **Ratio:** 206:1 (flood vs malformed)
- **Impact:** Model will be biased toward majority class (flood)
- **Action:** Use `class_weight='balanced'` in RandomForest and stratified sampling

---

## 6. Recommendations for Colab Notebook

### ✅ Data Loading
```python
# Load dataset
df_raw = pd.read_csv('FINAL_LLDP_DATASET_COMPLETE_enriched.csv')

# Validate size (must be >= 100,000 rows)
if df_raw.shape[0] < 100000:
    raise ValueError(f"Wrong dataset! Expected 108K rows, got {df_raw.shape[0]:,}")
```

### ✅ Data Cleaning
```python
# 1. Remove duplicates (2.2%)
df = df_raw.drop_duplicates()

# 2. Drop completely empty features
df = df.drop(columns=['size_z_src'])  # 100% missing

# 3. Drop highly sparse features (optional but recommended)
df = df.drop(columns=['packet_rate_inst', 'burstiness_cv'])  # >90% missing
```

### ✅ Feature Selection
Use only the **18 complete features**:
- timestamp, time_epoch, eth_src, eth_dst
- packet_size, ttl, tlv_count
- inter_frame_delta (96% filled - handle with median imputation)
- packet_rate_win, ttl_dev, ttl_anom_flag
- tlv_density, is_lldp_mc, age_since_first
- time_delta, packet_rate, t_bin, count_win

### ✅ Handle inter_frame_delta (3.9% missing)
```python
# Median imputation for inter_frame_delta (only 3.9% missing)
df['inter_frame_delta'].fillna(df['inter_frame_delta'].median(), inplace=True)
```

### ✅ Class Imbalance Handling
```python
# Use class weighting
rf = RandomForestClassifier(
    class_weight='balanced',  # Handles 206:1 imbalance
    random_state=42
)

# Stratified train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,  # Preserves class distribution
    random_state=42
)
```

### ✅ Evaluation Metrics
```python
# Use F1-Macro (equal weight to all classes)
scoring='f1_macro'

# Monitor per-class metrics
print(classification_report(y_test, y_pred))

# Check confusion matrix for minority classes
print(confusion_matrix(y_test, y_pred))
```

---

## 7. What Might Have Caused Your Colab Failure?

### Hypothesis 1: Wrong Dataset File ❌
**Your symptom:** "Dataset: 17,366 rows x 22 columns"
- You uploaded a **different file** (not FINAL_LLDP_DATASET_COMPLETE_enriched.csv)
- The correct file has **108,297 rows**
- **Solution:** Upload the correct file from `ramifinal655/mlmodel/data/`

### Hypothesis 2: Pandas/Numpy Not Installed ❌
- Colab usually has pandas pre-installed
- But if using a custom runtime, packages might be missing
- **Solution:** Run `!pip install pandas numpy scikit-learn` first

### Hypothesis 3: Memory Issues ❌
- 18 MB dataset is very small (should fit easily in RAM)
- Colab free tier has 12 GB RAM
- **Solution:** This is unlikely to be the issue

### Hypothesis 4: Feature Handling Errors ✅ **LIKELY**
- The notebook tried to use `size_z_src` (100% missing)
- The notebook tried to use `packet_rate_inst` or `burstiness_cv` (>90% missing)
- This caused errors during preprocessing or training
- **Solution:** Updated notebook now drops these features and validates data

### Hypothesis 5: Encoding Issues ❌
- MAC addresses (eth_src, eth_dst) need proper encoding
- If not handled, this causes errors
- **Solution:** Updated notebook uses proper feature selection

---

## 8. Expected Results After Fixes

### Expected Dataset Stats
```
Dataset loaded: 108,297 rows x 22 columns
Validation: PASS (size >= 100,000 rows)

Class Distribution:
  flood          : 87,866 (81.2%)
  replay         : 12,560 (11.6%)
  normal         :  6,045 ( 5.6%)
  spoofed        :    800 ( 0.7%)
  ttl_anomaly    :    600 ( 0.6%)
  malformed      :    426 ( 0.4%)

Imbalance Ratio: 206.21:1
```

### Expected After Deduplication
```
After deduplication: 105,932 rows (2,365 removed, 2.2%)
```

### Expected Feature Count
```
Features selected: 16-18 features
(Dropped: size_z_src, packet_rate_inst, burstiness_cv)
```

### Expected Model Performance
With proper class balancing:
- **Overall F1-Macro:** 0.85-0.95 (high)
- **Normal:** High precision/recall (large class)
- **Flood:** High precision/recall (largest class)
- **Replay:** Medium-high precision/recall (12K samples)
- **Spoofed/TTL anomaly/Malformed:** Lower metrics (small classes, <1000 samples each)

---

## 9. Action Items

### For You:
1. ✅ **Upload correct dataset to Colab:** `/content/FINAL_LLDP_DATASET_COMPLETE_enriched.csv`
2. ✅ **Use the updated notebook:** `LLDP_IDS_ML_Pipeline.ipynb` (already fixed with validation)
3. ✅ **Run all cells** and verify you see "Validation: PASS"
4. ✅ **Check class distribution** matches the expected output above
5. ✅ **Monitor training** for convergence and no errors

### For the Notebook (already fixed):
1. ✅ Dataset size validation (catches wrong file)
2. ✅ Drop size_z_src (100% missing)
3. ✅ Drop packet_rate_inst and burstiness_cv (>90% missing)
4. ✅ Handle inter_frame_delta with median imputation
5. ✅ Use class_weight='balanced'
6. ✅ Stratified train-test split
7. ✅ F1-Macro scoring
8. ✅ Per-class metrics reporting

---

## 10. Summary

### Dataset Status: ✅ **READY FOR PROCESSING**

The dataset `FINAL_LLDP_DATASET_COMPLETE_enriched.csv` is **valid and complete** with 108,297 rows matching the expected distribution. The main issues are:

1. **Sparse features** (packet_rate_inst, burstiness_cv, size_z_src) - **DROP THESE**
2. **Class imbalance** (206:1) - **USE class_weight='balanced'**
3. **Small duplicate percentage** (2.2%) - **REMOVE with drop_duplicates()**
4. **Minor missing data** in inter_frame_delta (3.9%) - **IMPUTE with median**

The updated Colab notebook (`LLDP_IDS_ML_Pipeline.ipynb`) now handles all these issues correctly.

### What Caused Your Previous Failure:
**Most likely:** You uploaded the **wrong dataset file** (17K rows instead of 108K). The updated notebook now validates this and will raise an error immediately if the wrong file is uploaded.

### Next Steps:
1. Upload the correct dataset: `ramifinal655/mlmodel/data/FINAL_LLDP_DATASET_COMPLETE_enriched.csv`
2. Open `LLDP_IDS_ML_Pipeline.ipynb` in Colab
3. Upload the CSV to `/content/` (not Drive)
4. Run all cells
5. You should see "Validation: PASS" and proper class distribution

---

**Report Generated:** 2025-11-21
**Analyst:** Claude (AI Assistant)
**Branch:** claude/setup-ids-project-01P3KnjqzpbcbmiAHHWsE4j6
