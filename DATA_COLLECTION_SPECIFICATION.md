# LLDP IDS Data Collection Specification

**Project:** LLDP-based Topology Poisoning IDS for SDN
**Attack Script:** ramifinal655/scapy_lldp_attacks.py (9 attack modes)
**ML Approach:** Random Forest flow-based behavioral detection

---

## 1. YOUR ATTACK CAPABILITIES

Based on your finalized attack script, you can generate:

### Attack Types (9 modes)
1. **Spoof** - Inject fake LLDP packets with spoofed switch identity
2. **Flood** - High-rate LLDP packet flood with random MAC addresses
3. **TTL Anomaly** - LLDP packets with abnormal TTL values (0, very low, very high)
4. **Malformed** - LLDP packets with corrupted/invalid TLV structures
5. **Relay (MITM)** - Intercept and forward legitimate LLDP packets
6. **Replay** - Replay captured LLDP packets from PCAP files
7. **Discovery** - Randomized discovery probes to map topology
8. **Capture** - Passive sniffing of LLDP traffic
9. **Suite** - Sequential execution of all attacks

### Attack Parameters You Control
- Rate (packets per second): 1-1000+ pps
- Duration: seconds to hours
- Burst capacity: TokenBucket rate limiting
- Jitter: timing randomization
- VLAN tagging: IEEE 802.1Q support
- Chassis ID: spoofed switch identity
- Port ID: spoofed port identity
- TTL values: 0-65535 (normal=120)
- TLV count: 5 (normal), 6+ (with org-specific)
- Custom organizational TLVs

---

## 2. DATA YOU MUST COLLECT

### A. PACKET-LEVEL FEATURES (Raw LLDP Capture)

**Critical LLDP Fields:**
```
timestamp           - Packet arrival time (microsecond precision)
eth_src             - Source MAC address
eth_dst             - Destination MAC (should be 01:80:c2:00:00:0e)
packet_size         - Total frame size in bytes
ttl                 - Time To Live value
tlv_count           - Number of TLVs in packet
chassis_id          - Switch chassis identifier
port_id             - Port identifier
system_name         - Optional system name TLV
system_desc         - Optional system description
port_desc           - Optional port description
vlan_id             - VLAN tag (if present)
org_specific_count  - Number of organizational-specific TLVs
is_valid_lldp       - Boolean: valid LLDP structure
is_multicast_dst    - Boolean: dst == 01:80:c2:00:00:0e
```

**Why these matter:**
- `ttl`: 0 or very low = TTL anomaly attack
- `eth_src`: Randomized = flood attack, spoofed = spoof attack
- `tlv_count`: Abnormal count = malformed attack
- `packet_size`: 60 bytes (normal), 64+ bytes (extra TLVs)
- `chassis_id`: Changes frequently = discovery/spoof attack

### B. FLOW-LEVEL FEATURES (Time-Window Aggregation)

**Per-Source Flow Features (5-30 second windows):**
```
packet_rate         - Packets per second from this source
packet_count        - Total packets in window
byte_count          - Total bytes in window
inter_frame_delta   - Time between consecutive packets (seconds)
packet_rate_inst    - Instantaneous rate (1/inter_frame_delta)
burstiness_cv       - Coefficient of variation of inter-arrival times
age_since_first     - Time since first packet from this source
time_delta          - Time since last packet
unique_chassis_ids  - Number of unique chassis IDs from this MAC
unique_port_ids     - Number of unique port IDs from this MAC
ttl_variance        - Variance of TTL values
ttl_dev             - TTL deviation from expected (120)
tlv_density         - TLVs per packet (tlv_count / packet_size)
avg_packet_size     - Average packet size
size_variance       - Variance of packet sizes
```

**Why these matter:**
- `packet_rate`: >30 pps = flood attack (normal: 0.5-1 pps every 30-120s)
- `burstiness_cv`: High = bursty flood, Low = steady normal
- `unique_chassis_ids`: >1 from same MAC = spoof/discovery
- `ttl_variance`: High = TTL anomaly attack
- `inter_frame_delta`: <0.1s = flood, ~30-120s = normal

### C. TOPOLOGY-LEVEL FEATURES (Controller View)

**Per-Link Statistics:**
```
link_count          - Number of discovered links
link_stability      - How often link state changes
duplicate_links     - Links with same endpoints
phantom_links       - Links to non-existent switches
inconsistent_ports  - Port mismatches in bidirectional discovery
lldp_source_count   - Number of sources claiming to be same switch
topology_churn      - Rate of topology changes
```

**Why these matter:**
- `duplicate_links`: Relay/MITM attack
- `phantom_links`: Spoof attack
- `topology_churn`: Discovery/flood attack
- `lldp_source_count`: >1 MAC claiming same chassis = spoof

### D. CONTEXTUAL FEATURES (Ground Truth)

```
label               - Attack class: normal, spoof, flood, ttl_anomaly,
                      malformed, relay, replay, discovery
switch_exists       - Boolean: chassis_id exists in real topology
port_exists         - Boolean: port_id exists on claimed switch
is_bidirectional    - Boolean: reverse LLDP seen from neighbor
rtt_anomaly         - Boolean: round-trip time inconsistent
expected_ttl        - Expected TTL value (120 for standard LLDP)
ttl_anom_flag       - Boolean: |ttl - 120| > threshold
```

---

## 3. DATA COLLECTION METHODOLOGY

### Recommended Testbed Setup

**Network Topology:**
```
┌─────────────┐
│ Ryu/ONOS/   │
│ ODL         │  ← SDN Controller
│ Controller  │
└──────┬──────┘
       │ OpenFlow
  ┌────┴─────────────┬──────────┐
  │                  │          │
┌─▼──┐          ┌───▼─┐    ┌──▼──┐
│ s1 │──────────│ s2  │────│ s3  │  ← OpenFlow Switches
└──┬─┘          └─────┘    └──┬──┘
   │                          │
┌──▼───┐                  ┌──▼───┐
│ h1   │                  │ h2   │  ← Hosts
└──────┘                  └──────┘
   │
┌──▼───────┐
│ Attacker │  ← Your attack script
└──────────┘
```

**Capture Points:**
1. **Mirror port on switches** - Capture all LLDP traffic (eth_dst=01:80:c2:00:00:0e)
2. **Controller northbound API** - Topology view from controller
3. **OpenFlow statistics** - Flow table entries, packet counts

### Collection Process

**Phase 1: Baseline Normal Traffic (30-60 minutes)**
```bash
# Let switches run normally with LLDP discovery
# Capture: 1000-2000 normal LLDP packets
# Expected rate: 1 packet per switch per 30-120 seconds
```

**Phase 2: Individual Attack Campaigns (10-15 min each)**
```bash
# Spoof Attack
python3 scapy_lldp_attacks.py --mode spoof --iface eth0 \
  --chassis "fake-switch-001" --rate 30 --duration 600

# Flood Attack
python3 scapy_lldp_attacks.py --mode flood --iface eth0 \
  --rate 100 --duration 600

# TTL Anomaly
python3 scapy_lldp_attacks.py --mode ttl_anomaly --iface eth0 \
  --ttl-anom-val 0 --rate 10 --duration 600

# Malformed TLV
python3 scapy_lldp_attacks.py --mode malformed --iface eth0 \
  --rate 20 --duration 600

# Relay (requires 2 interfaces)
python3 scapy_lldp_attacks.py --mode relay --iface eth0 \
  --out-iface eth1 --duration 600

# Replay (requires captured PCAP)
python3 scapy_lldp_attacks.py --mode replay --iface eth0 \
  --pcap-in normal_lldp.pcap --rate 50 --duration 600

# Discovery
python3 scapy_lldp_attacks.py --mode discovery --iface eth0 \
  --rate 10 --duration 600
```

**Phase 3: Mixed Traffic (30-60 minutes)**
```bash
# Run suite mode multiple times with varying parameters
# Interleave with normal traffic periods
# Vary attack intensities (rate: 5, 10, 50, 100 pps)
```

### Feature Extraction Pipeline

```python
# Pseudocode for feature extraction

# 1. Parse PCAP and extract packet-level features
for packet in pcap:
    extract_lldp_fields(packet)

# 2. Aggregate into flow windows (30-second windows)
for window in time_windows:
    flows = group_by_source_mac(packets_in_window)
    for flow in flows:
        compute_flow_features(flow)

# 3. Merge with topology context
for flow in flows:
    add_topology_features(flow, controller_api)

# 4. Label data
for flow in flows:
    flow['label'] = get_attack_type_from_metadata(flow.timestamp)
```

---

## 4. DATASET QUALITY REQUIREMENTS

### Size Requirements
```
Minimum samples per class:
  normal:       50,000+    (largest class, 70-80% of total)
  flood:        30,000+    (common attack, 15-20%)
  spoof:        5,000+     (5-8%)
  replay:       5,000+     (5-8%)
  ttl_anomaly:  2,000+     (2-3%)
  malformed:    2,000+     (2-3%)
  relay:        2,000+     (2-3%)
  discovery:    2,000+     (2-3%)

Total minimum: 100,000+ samples
Recommended:   500,000+ samples
```

### Diversity Requirements
```
Rate diversity:
  - Normal: 0.5-1 pps (30-120s intervals)
  - Light attacks: 5-10 pps
  - Medium attacks: 20-50 pps
  - Heavy attacks: 100-500 pps

TTL diversity:
  - Normal: 120 (>95% of samples)
  - Anomaly: 0, 1-10, 200-255 (distributed)

Topology diversity:
  - Linear: 2-5 switches
  - Tree: 3-7 switches (depth 2-3)
  - Mesh: 4-9 switches (partial/full mesh)
```

### Temporal Requirements
```
Attack duration variety:
  - Short bursts: 10-30 seconds
  - Medium: 1-5 minutes
  - Sustained: 10-30 minutes

Inter-attack gaps:
  - 2-5 minutes of normal traffic between attacks
  - Ensures clear attack boundaries
```

### Data Quality Checks
```
Duplicate rate: <5% (your current: 90.9% - FAILED)
Missing values: <10% per feature (your current: 97.6% for some - FAILED)
Class imbalance: <100:1 ratio (your current: 206:1 - BORDERLINE)
Feature variance: All features must have stdev > 0
Label accuracy: 100% (ground truth from attack metadata)
```

---

## 5. EXISTING DATASET EVALUATION

### InSDN Dataset (2020)
**URL:** https://www.unb.ca/cic/datasets/ids-2017.html
**Download:** https://aseados.ucd.ie/

**Pros:**
- SDN-specific (OpenFlow environment)
- 343,939 samples
- Well-labeled (normal + 7 attack types)
- Publicly available

**Cons:**
- No LLDP-specific attacks
- Focuses on: DoS, DDoS, Web attacks, Botnet, Brute force, Probes
- No topology poisoning coverage
- No LLDP protocol features

**Verdict:** NOT SUITABLE for your LLDP IDS project

### SDNFlow Dataset (2023)
**URL:** https://ieee-dataport.org/documents/sdnflow-dataset

**Pros:**
- Recent (2023)
- OpenFlow statistics-based
- 98-99% detection accuracy demonstrated
- Real traffic from OpenFlow switches

**Cons:**
- Focus on general network attacks (not LLDP-specific)
- Unknown if LLDP features included
- May require IEEE membership for download

**Verdict:** POSSIBLY USEFUL - Need to verify LLDP feature availability

### UNR-IDD Dataset
**Features:** Port-level statistics from OpenFlow

**Pros:**
- SDN simulation environment
- OpenFlow-based

**Cons:**
- Port statistics only (not packet-level LLDP)
- No confirmed LLDP attack coverage

**Verdict:** NOT SUITABLE

### DIS-Guard RCO Attack Dataset (2024)
**Paper:** https://www.sciencedirect.com/science/article/abs/pii/S1389128624005553

**Pros:**
- Recent (2024)
- Specifically for topology attacks
- Round-trip time confusion attacks
- Varying topology sizes

**Cons:**
- Availability unknown (research dataset)
- Focus on RCO attacks (not comprehensive LLDP attacks)

**Verdict:** CHECK AVAILABILITY - May need to contact authors

### SecTopo Dataset (2025)
**Paper:** https://www.sciencedirect.com/science/article/abs/pii/S1389128625004773

**Pros:**
- Very recent (2025)
- Specifically for LLDP topology poisoning
- Includes poison, flood, replay attacks
- 98.76% detection accuracy achieved

**Cons:**
- Availability unknown (very recent)
- May be proprietary research data

**Verdict:** HIGH PRIORITY - Contact authors for dataset access

---

## 6. RECOMMENDED NEW DATASET SOURCES

### Option 1: Generate Your Own (RECOMMENDED)

**Why:**
- You have complete attack script (9 modes)
- Full control over attack parameters
- Can ensure data quality
- Matches your exact research scope

**How:**
1. Set up Mininet + Ryu/ONOS controller
2. Run your attack script in controlled environment
3. Capture at mirror port + controller API
4. Follow Phase 1-3 collection process above
5. Extract features using Scapy + pandas

**Timeline:** 2-3 weeks
**Cost:** Free (local VM/server)

### Option 2: Request Research Datasets

**Targets:**
1. **SecTopo authors** (2025) - Most relevant
   - Email: Check paper author contacts
   - Request: Dataset + ground truth labels

2. **DIS-Guard authors** (2024)
   - Focus on RCO + topology attacks

3. **SDNFlow authors** (2023)
   - Request: Verify if LLDP features present

### Option 3: Public Dataset Repositories

**Check these sources:**

1. **IEEE DataPort** - https://ieee-dataport.org/
   - Search: "SDN", "LLDP", "topology poisoning"

2. **Kaggle Datasets** - https://www.kaggle.com/datasets
   - Search: "SDN security", "network intrusion"

3. **UC Irvine ML Repository** - https://archive.ics.uci.edu/
   - Filter: Network security

4. **UNB CIC Datasets** - https://www.unb.ca/cic/datasets/
   - Check new SDN-specific uploads

5. **GitHub Dataset Collections**
   - https://github.com/shramos/Awesome-Cybersecurity-Datasets
   - https://github.com/gfek/Real-CyberSecurity-Datasets

---

## 7. DATASET CHECKLIST

When evaluating a dataset, verify:

### Must-Have Features
```
[ ] Packet-level LLDP fields:
    [ ] timestamp (microsecond precision)
    [ ] eth_src, eth_dst
    [ ] ttl
    [ ] tlv_count
    [ ] packet_size
    [ ] chassis_id (or derivable from packet)
    [ ] port_id (or derivable from packet)

[ ] Flow-level features:
    [ ] packet_rate or packet_count per time window
    [ ] inter_frame_delta or inter-arrival times
    [ ] Time-based aggregation (windows)

[ ] Attack labels:
    [ ] Binary: normal vs attack
    [ ] Multi-class: specific attack types
    [ ] Timestamps for attack start/end

[ ] Sample size:
    [ ] Total: >100,000 samples
    [ ] Per class: >2,000 samples for minority classes
```

### Nice-to-Have Features
```
[ ] Topology context (controller view)
[ ] Bidirectional link verification flags
[ ] RTT measurements
[ ] Flow table statistics
[ ] Switch-level features
[ ] Multiple topology types (linear, tree, mesh)
```

### Data Quality Checks
```
[ ] Duplicate rate <5%
[ ] Missing values <10% per feature
[ ] Class imbalance <100:1
[ ] Attack types cover your 9 modes (or subset)
[ ] Ground truth labels verified
[ ] Metadata included (attack parameters)
```

### Format Requirements
```
[ ] CSV or Parquet (easy to load in pandas)
[ ] PCAP files available (for feature re-extraction)
[ ] Documentation of features (data dictionary)
[ ] Example code for loading data
[ ] Train/test split provided or splittable
```

---

## 8. FEATURE EXTRACTION CODE TEMPLATE

```python
import pandas as pd
from scapy.all import rdpcap, Ether
from collections import defaultdict
import numpy as np

def extract_lldp_features(pcap_file, window_size=30):
    """
    Extract LLDP features from PCAP file.

    Args:
        pcap_file: Path to PCAP containing LLDP traffic
        window_size: Time window in seconds for flow aggregation

    Returns:
        DataFrame with packet-level and flow-level features
    """

    packets = rdpcap(pcap_file)
    features = []

    # Extract packet-level features
    for pkt in packets:
        if pkt.haslayer(Ether) and pkt[Ether].type == 0x88cc:  # LLDP
            pkt_features = {
                'timestamp': float(pkt.time),
                'eth_src': pkt[Ether].src,
                'eth_dst': pkt[Ether].dst,
                'packet_size': len(pkt),
                'ttl': extract_ttl(pkt),
                'tlv_count': count_tlvs(pkt),
                'chassis_id': extract_chassis_id(pkt),
                'port_id': extract_port_id(pkt),
                'is_lldp_mc': pkt[Ether].dst == '01:80:c2:00:00:0e',
            }
            features.append(pkt_features)

    df = pd.DataFrame(features)

    # Add flow-level features
    df = add_flow_features(df, window_size)

    return df

def add_flow_features(df, window_size):
    """Aggregate packet-level into flow-level features."""

    # Sort by timestamp
    df = df.sort_values('timestamp')

    # Create time bins
    df['t_bin'] = (df['timestamp'] // window_size).astype(int)

    # Group by source MAC and time bin
    flow_features = []
    for (src, t_bin), group in df.groupby(['eth_src', 't_bin']):
        flow = {
            'eth_src': src,
            't_bin': t_bin,
            'timestamp': group['timestamp'].iloc[0],

            # Rate features
            'packet_count': len(group),
            'packet_rate': len(group) / window_size,

            # Inter-arrival features
            'inter_frame_delta': group['timestamp'].diff().mean(),
            'burstiness_cv': group['timestamp'].diff().std() / group['timestamp'].diff().mean()
                             if len(group) > 1 else 0,

            # TTL features
            'ttl_mean': group['ttl'].mean(),
            'ttl_dev': abs(group['ttl'].mean() - 120),
            'ttl_anom_flag': int(abs(group['ttl'].mean() - 120) > 10),

            # Size features
            'packet_size_mean': group['packet_size'].mean(),
            'tlv_count_mean': group['tlv_count'].mean(),
            'tlv_density': group['tlv_count'].sum() / group['packet_size'].sum(),

            # Diversity features
            'unique_chassis_ids': group['chassis_id'].nunique(),
            'unique_port_ids': group['port_id'].nunique(),

            # Temporal features
            'age_since_first': group['timestamp'].iloc[-1] - group['timestamp'].iloc[0],
            'time_delta': group['timestamp'].diff().iloc[-1],
        }
        flow_features.append(flow)

    return pd.DataFrame(flow_features)

def extract_ttl(pkt):
    """Extract TTL from LLDP packet."""
    if pkt.haslayer('LLDPDUTimeToLive'):
        return pkt['LLDPDUTimeToLive'].ttl
    return 120  # Default

def count_tlvs(pkt):
    """Count TLVs in LLDP packet."""
    count = 0
    layer = pkt.getlayer('LLDPDU')
    while layer:
        count += 1
        layer = layer.payload.getlayer('LLDPDU')
    return count

def extract_chassis_id(pkt):
    """Extract chassis ID from LLDP."""
    if pkt.haslayer('LLDPDUChassisID'):
        return pkt['LLDPDUChassisID'].id.decode('utf-8', errors='ignore')
    return 'unknown'

def extract_port_id(pkt):
    """Extract port ID from LLDP."""
    if pkt.haslayer('LLDPDUPortID'):
        return pkt['LLDPDUPortID'].id.decode('utf-8', errors='ignore')
    return 'unknown'
```

---

## 9. IMMEDIATE ACTION PLAN

### Week 1: Dataset Search
```
Day 1-2: Contact SecTopo and DIS-Guard authors for datasets
Day 3-4: Download and evaluate SDNFlow, InSDN datasets
Day 5-7: Test your attack script in Mininet environment
```

### Week 2-3: Data Generation (if no suitable dataset found)
```
Day 1-3: Set up Mininet + controller + capture setup
Day 4-6: Collect baseline normal traffic (Phase 1)
Day 7-14: Run attack campaigns (Phase 2)
Day 15-18: Collect mixed traffic (Phase 3)
Day 19-21: Feature extraction and validation
```

### Week 4: Data Preparation
```
Day 1-3: Feature engineering and cleaning
Day 4-5: Train/test split (stratified, 80/20)
Day 6-7: Data quality validation
```

---

## 10. CRITICAL SUCCESS METRICS

Your dataset is ready when:

```
[✓] 100,000+ total samples
[✓] <5% duplicate rate (NOT 90.9%)
[✓] <10% missing values per feature (NOT 97.6%)
[✓] All 8 attack classes represented (or justify subset)
[✓] Imbalance ratio <100:1 (ideally <50:1)
[✓] Feature variance: all features have stdev > 0
[✓] Temporal diversity: attacks of varying durations
[✓] Rate diversity: attacks at 5, 10, 50, 100+ pps
[✓] Can achieve >90% F1-score with baseline RF model
[✓] <10% false positive rate for all classes
```

---

## FINAL RECOMMENDATIONS

### Primary Path: Generate Your Own Dataset
**Reason:** Your current dataset has 90.9% duplicates and 97.6% missing values. This is unrecoverable. Starting fresh with proper collection will be faster than trying to fix existing data.

### Backup Path: SecTopo Dataset (2025)
**Action:** Contact authors immediately to request dataset access. This is the most recent and relevant dataset for your exact use case.

### Why Other Datasets Won't Work:
- InSDN: No LLDP attacks
- SDNFlow: Unknown LLDP coverage
- General network datasets: Wrong protocol layer

### Time Investment:
- Finding suitable dataset: 1-2 weeks (uncertain success)
- Generating your own: 2-3 weeks (guaranteed success)

**Verdict: Generate your own dataset using your attack script.**
