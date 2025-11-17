#!/usr/bin/env python3
"""
IDS Performance Benchmark and Visualization
Parses IDS logs, computes metrics, generates plots.

References:
- pandas.pydata.org/docs (log parsing to DataFrame)
- matplotlib.org (plotting library)
"""

import os
import re
import sys
from datetime import datetime
from collections import defaultdict

# Headless plotting for server environments
# From: matplotlib.org (backend configuration)
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

import pandas as pd
import numpy as np


# LOG PARSING
# From: pandas.pydata.org (text parsing to structured data)
def parse_ids_log(log_file):
    """Parse IDS log file into structured data."""

    if not os.path.exists(log_file):
        print(f"Error: {log_file} not found")
        sys.exit(1)

    records = []

    with open(log_file, 'r') as f:
        for line in f:
            # Parse normal classifications
            # Format: ... - INFO - Normal: <class> (<conf>%) | Latency: <lat>ms
            normal_match = re.search(r'Normal: (\w+) \((\d+\.\d+)%\) \| Latency: (\d+\.\d+)ms', line)
            if normal_match:
                records.append({
                    'timestamp': _parse_timestamp(line),
                    'type': 'normal',
                    'class': normal_match.group(1),
                    'confidence': float(normal_match.group(2)),
                    'latency_ms': float(normal_match.group(3))
                })
                continue

            # Parse attack detections
            # Format: ... - WARNING - ATTACK: <TYPE>
            attack_match = re.search(r'ATTACK: (\w+)', line)
            if attack_match:
                records.append({
                    'timestamp': _parse_timestamp(line),
                    'type': 'attack',
                    'class': attack_match.group(1).lower(),
                    'confidence': None,
                    'latency_ms': None
                })
                continue

            # Parse latency from attack logs
            # Format: ... Confidence: <conf>% | Latency: <lat>ms
            lat_match = re.search(r'Confidence: (\d+\.\d+)% \| Latency: (\d+\.\d+)ms', line)
            if lat_match and records and records[-1]['type'] == 'attack':
                records[-1]['confidence'] = float(lat_match.group(1))
                records[-1]['latency_ms'] = float(lat_match.group(2))

    return pd.DataFrame(records)

def _parse_timestamp(log_line):
    """Extract timestamp from log line."""
    match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', log_line)
    if match:
        return pd.to_datetime(match.group(1))
    return None


# METRICS COMPUTATION
def compute_metrics(df):
    """Calculate IDS performance metrics."""

    total = len(df)
    normal = len(df[df['type'] == 'normal'])
    attacks = len(df[df['type'] == 'attack'])

    # Latency stats (from: numpy docs)
    latencies = df['latency_ms'].dropna()

    metrics = {
        'total_packets': total,
        'normal_packets': normal,
        'attacks_detected': attacks,
        'detection_rate': (attacks / total * 100) if total > 0 else 0.0,
        'latency_avg_ms': latencies.mean() if len(latencies) > 0 else 0.0,
        'latency_median_ms': latencies.median() if len(latencies) > 0 else 0.0,
        'latency_p95_ms': latencies.quantile(0.95) if len(latencies) > 0 else 0.0,
        'latency_p99_ms': latencies.quantile(0.99) if len(latencies) > 0 else 0.0
    }

    # Attack type breakdown
    attack_counts = df[df['type'] == 'attack']['class'].value_counts().to_dict()
    metrics['attacks_by_type'] = attack_counts

    return metrics


# VISUALIZATION
# From: matplotlib.org (plotting API)
def generate_plots(df, output_dir):
    """Generate performance visualization plots."""

    os.makedirs(output_dir, exist_ok=True)

    # 1. Latency Histogram
    latencies = df['latency_ms'].dropna()
    if len(latencies) > 0:
        plt.figure(figsize=(10, 6))
        plt.hist(latencies, bins=50, color='steelblue', edgecolor='black', alpha=0.7)
        plt.axvline(latencies.quantile(0.95), color='red', linestyle='--', label=f'P95: {latencies.quantile(0.95):.2f}ms')
        plt.xlabel('Latency (ms)')
        plt.ylabel('Frequency')
        plt.title('IDS Detection Latency Distribution')
        plt.legend()
        plt.grid(alpha=0.3)
        plt.savefig(f'{output_dir}/latency_hist.png', dpi=300, bbox_inches='tight')
        plt.close()

    # 2. Attacks by Type
    attacks = df[df['type'] == 'attack']
    if len(attacks) > 0:
        attack_counts = attacks['class'].value_counts()
        plt.figure(figsize=(10, 6))
        attack_counts.plot(kind='bar', color='crimson', edgecolor='black')
        plt.xlabel('Attack Type')
        plt.ylabel('Count')
        plt.title('Attacks Detected by Type')
        plt.xticks(rotation=45)
        plt.grid(axis='y', alpha=0.3)
        plt.savefig(f'{output_dir}/attacks_bar.png', dpi=300, bbox_inches='tight')
        plt.close()

    # 3. Throughput over Time
    if 'timestamp' in df.columns and df['timestamp'].notna().any():
        df_sorted = df.sort_values('timestamp')
        df_sorted['time_delta'] = (df_sorted['timestamp'] - df_sorted['timestamp'].min()).dt.total_seconds()

        # Events per second (1-second bins)
        bins = np.arange(0, df_sorted['time_delta'].max() + 1, 1.0)
        throughput, _ = np.histogram(df_sorted['time_delta'], bins=bins)

        plt.figure(figsize=(12, 6))
        plt.plot(bins[:-1], throughput, color='green', linewidth=2)
        plt.xlabel('Time (seconds)')
        plt.ylabel('Events/second')
        plt.title('IDS Throughput Over Time')
        plt.grid(alpha=0.3)
        plt.savefig(f'{output_dir}/throughput.png', dpi=300, bbox_inches='tight')
        plt.close()


# CSV EXPORT
# From: pandas.pydata.org (DataFrame to CSV)
def export_metrics(metrics, df, output_dir):
    """Export metrics to CSV."""

    # Summary metrics
    summary = pd.DataFrame([{
        'metric': k,
        'value': v if not isinstance(v, dict) else str(v)
    } for k, v in metrics.items()])
    summary.to_csv(f'{output_dir}/metrics.csv', index=False)

    # Full event log
    df.to_csv(f'{output_dir}/events.csv', index=False)

    print(f"Exported: {output_dir}/metrics.csv")
    print(f"Exported: {output_dir}/events.csv")


# MAIN EXECUTION
def main():
    log_file = 'lldp_ids_alerts.log'
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = f'runs/{timestamp}'

    print("LLDP IDS Performance Benchmark")
    print("="*60)

    # Parse logs
    print(f"Parsing: {log_file}")
    df = parse_ids_log(log_file)
    print(f"Loaded {len(df)} events")

    if df.empty:
        print("No data to process")
        return

    # Compute metrics
    print("\nComputing metrics...")
    metrics = compute_metrics(df)

    print("\nMetrics:")
    print(f"  Total Packets: {metrics['total_packets']}")
    print(f"  Normal: {metrics['normal_packets']}")
    print(f"  Attacks: {metrics['attacks_detected']}")
    print(f"  Detection Rate: {metrics['detection_rate']:.2f}%")
    print(f"  Latency Avg: {metrics['latency_avg_ms']:.2f}ms")
    print(f"  Latency P95: {metrics['latency_p95_ms']:.2f}ms")
    if metrics['attacks_by_type']:
        print(f"  Attack Types: {metrics['attacks_by_type']}")

    # Generate plots
    print(f"\nGenerating plots: {output_dir}")
    generate_plots(df, output_dir)

    # Export CSVs
    export_metrics(metrics, df, output_dir)

    print("\nDone!")
    print(f"Results saved to: {output_dir}/")


if __name__ == '__main__':
    main()
